#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/proxy.py - 智能代理IP池 v2.0
支持HTTP/HTTPS/SOCKS5代理，自动健康检查，失败自动切换，轮询负载均衡
"""

import random
import threading
import time
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class ProxyProtocol(Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS5 = "socks5"


@dataclass
class Proxy:
    url: str
    protocol: ProxyProtocol
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    failures: int = 0
    last_used: float = 0
    success_count: int = 0
    fail_count: int = 0
    
    @property
    def is_healthy(self) -> bool:
        return self.failures < 3
    
    def mark_success(self):
        self.success_count += 1
        self.failures = max(0, self.failures - 1)
        self.last_used = time.time()
    
    def mark_failure(self):
        self.fail_count += 1
        self.failures += 1
        self.last_used = time.time()
    
    def to_requests_dict(self) -> Dict[str, str]:
        return {
            "http": self.url,
            "https": self.url
        }


class ProxyPool:
    """
    智能代理IP池
    
    特性：
    - 支持HTTP/HTTPS/SOCKS5多种协议
    - 支持用户名密码认证
    - 自动健康检查，连续失败自动隔离
    - 轮询+随机两种选择策略
    - 线程安全
    """
    
    def __init__(self, proxy_file: Optional[str] = None, proxies: Optional[List[str]] = None):
        self._lock = threading.RLock()
        self._proxies: List[Proxy] = []
        self._current_idx = 0
        
        if proxy_file:
            self.load_from_file(proxy_file)
        if proxies:
            self.add_proxies(proxies)

    def _parse_proxy_url(self, url: str) -> Optional[Proxy]:
        """解析代理URL为Proxy对象"""
        try:
            url = url.strip()
            if not url or url.startswith("#"):
                return None
            
            # 解析协议
            if "://" not in url:
                url = "http://" + url
            
            protocol_part, rest = url.split("://", 1)
            protocol = ProxyProtocol.HTTP
            if protocol_part.lower() == "socks5":
                protocol = ProxyProtocol.SOCKS5
            elif protocol_part.lower() == "https":
                protocol = ProxyProtocol.HTTPS
            
            # 解析认证和地址
            username = password = None
            host_port = rest
            if "@" in rest:
                auth_part, host_port = rest.rsplit("@", 1)
                if ":" in auth_part:
                    username, password = auth_part.split(":", 1)
            
            # 解析host port
            host = host_port
            port = 8080
            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                port = int(port_str)
            
            return Proxy(
                url=url,
                protocol=protocol,
                host=host,
                port=port,
                username=username,
                password=password
            )
        except Exception:
            return None

    def load_from_file(self, filepath: str) -> int:
        """从文件加载代理列表，每行一个"""
        import os
        if not os.path.exists(filepath):
            return 0
        
        count = 0
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                proxy = self._parse_proxy_url(line)
                if proxy:
                    with self._lock:
                        self._proxies.append(proxy)
                        count += 1
        return count

    def add_proxy(self, proxy_url: str) -> bool:
        proxy = self._parse_proxy_url(proxy_url)
        if proxy:
            with self._lock:
                self._proxies.append(proxy)
            return True
        return False

    def add_proxies(self, proxy_urls: List[str]) -> int:
        count = 0
        for url in proxy_urls:
            if self.add_proxy(url):
                count += 1
        return count

    def get_proxy(self, strategy: str = "round_robin") -> Optional[Proxy]:
        """获取一个可用代理
        strategy: round_robin(轮询) / random(随机) / least_used(最少使用)
        """
        with self._lock:
            healthy = [p for p in self._proxies if p.is_healthy]
            if not healthy:
                # 所有代理都不健康，重置失败计数重新尝试
                for p in self._proxies:
                    p.failures = 0
                healthy = self._proxies
                if not healthy:
                    return None
            
            if strategy == "random":
                return random.choice(healthy)
            elif strategy == "least_used":
                return min(healthy, key=lambda p: p.last_used)
            else:  # round_robin
                proxy = healthy[self._current_idx % len(healthy)]
                self._current_idx = (self._current_idx + 1) % len(healthy)
                return proxy

    def get_requests_proxy(self) -> Optional[Dict[str, str]]:
        """获取requests库可用的代理dict格式"""
        proxy = self.get_proxy()
        return proxy.to_requests_dict() if proxy else None

    def report_success(self, proxy: Proxy):
        with self._lock:
            proxy.mark_success()

    def report_failure(self, proxy: Proxy):
        with self._lock:
            proxy.mark_failure()

    def __len__(self) -> int:
        with self._lock:
            return len(self._proxies)

    def healthy_count(self) -> int:
        with self._lock:
            return sum(1 for p in self._proxies if p.is_healthy)

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                "total": len(self._proxies),
                "healthy": self.healthy_count(),
                "total_success": sum(p.success_count for p in self._proxies),
                "total_fail": sum(p.fail_count for p in self._proxies),
            }
