#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/session.py - 安全HTTP会话工厂
集成SSL验证、自动重试、代理支持、随机User-Agent、请求速率控制
"""

import ssl
import random
from typing import Optional, Dict, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.proxy import ProxyPool, Proxy
from core.ratelimit import AdaptiveRateLimiter

USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.2478.97",
]


def create_secure_session(
    verify_ssl: bool = True,
    timeout: int = 10,
    retries: int = 2,
    proxy_pool: Optional[ProxyPool] = None,
    rate_limiter: Optional[AdaptiveRateLimiter] = None,
    random_ua: bool = True,
    custom_headers: Optional[Dict] = None,
) -> requests.Session:
    """
    创建配置好的安全requests会话
    
    Args:
        verify_ssl: 是否验证SSL证书
        timeout: 默认超时秒数
        retries: 失败重试次数
        proxy_pool: 代理池实例，自动轮询代理
        rate_limiter: 速率限制器，自动控制请求间隔
        random_ua: 是否随机User-Agent
        custom_headers: 自定义请求头
    
    Returns:
        配置好的requests.Session实例
    """
    session = requests.Session()
    
    # SSL配置
    session.verify = verify_ssl
    if not verify_ssl:
        requests.packages.urllib3.disable_warnings()
        ssl._create_default_https_context = ssl._create_unverified_context
    
    # 重试策略
    retry_strategy = Retry(
        total=retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=50, pool_maxsize=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # 默认请求头
    default_headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    
    if random_ua:
        default_headers["User-Agent"] = random.choice(USER_AGENTS)
    
    if custom_headers:
        default_headers.update(custom_headers)
    
    session.headers.update(default_headers)
    
    # 挂载扩展属性
    session.proxy_pool = proxy_pool
    session.rate_limiter = rate_limiter
    session.default_timeout = timeout
    
    # 绑定带速率限制和代理的请求方法
    _patch_session_request(session)
    
    return session


def _patch_session_request(session: requests.Session):
    """给session打补丁，自动处理代理轮询和速率限制"""
    original_request = session.request
    
    def patched_request(method, url, **kwargs):
        # 超时默认值
        kwargs.setdefault("timeout", session.default_timeout)
        
        # 速率限制等待
        if session.rate_limiter:
            session.rate_limiter.wait()
        
        # 代理选择
        proxy = None
        if session.proxy_pool:
            proxy = session.proxy_pool.get_proxy()
            if proxy:
                kwargs["proxies"] = proxy.to_requests_dict()
        
        try:
            resp = original_request(method, url, **kwargs)

            # 报告成功
            if proxy:
                session.proxy_pool.report_success(proxy)
            if session.rate_limiter:
                from core.ratelimit import ConnectionState
                if resp.status_code == 429:
                    # 429 = 明确被限流/封禁
                    session.rate_limiter.record_state(ConnectionState.CONN_REFUSED)
                elif resp.status_code in [401, 403]:
                    # 认证失败但服务正常响应
                    session.rate_limiter.record_state(ConnectionState.AUTH_FAIL)
                elif resp.status_code >= 500:
                    # 500/502/503/504 = 服务异常，不是成功
                    session.rate_limiter.record_state(ConnectionState.NO_RESPONSE)
                else:
                    session.rate_limiter.record_state(ConnectionState.SUCCESS)
            return resp
        except requests.exceptions.ProxyError:
            if proxy and session.proxy_pool:
                session.proxy_pool.report_failure(proxy)
            if session.rate_limiter:
                from core.ratelimit import ConnectionState
                session.rate_limiter.record_state(ConnectionState.NO_RESPONSE)
            raise
        except requests.exceptions.ConnectionError:
            if proxy and session.proxy_pool:
                session.proxy_pool.report_failure(proxy)
            if session.rate_limiter:
                from core.ratelimit import ConnectionState
                session.rate_limiter.record_state(ConnectionState.CONN_REFUSED)
            raise
        except requests.exceptions.Timeout:
            if proxy and session.proxy_pool:
                session.proxy_pool.report_failure(proxy)
            if session.rate_limiter:
                from core.ratelimit import ConnectionState
                session.rate_limiter.record_state(ConnectionState.TIMEOUT)
            raise
        except Exception:
            if proxy and session.proxy_pool:
                session.proxy_pool.report_failure(proxy)
            raise
    
    session.request = patched_request
