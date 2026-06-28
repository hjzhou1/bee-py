#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/ratelimit.py - 智能自适应速率控制器 v3.0
重新优化：默认速度快，遇到拦截才降速，提供fast/normal/safe三档预设
"""

import time
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional
from enum import Enum


class ConnectionState(Enum):
    """连接状态五类分类"""
    SUCCESS = "success"           # 连接成功+认证正常
    AUTH_FAIL = "auth_fail"       # 认证失败（密码错误但服务正常响应，不算拦截）
    CONN_REFUSED = "conn_refused" # 连接被拒绝（被防火墙/IP封禁拦截）
    TIMEOUT = "timeout"           # 请求超时
    NO_RESPONSE = "no_response"   # 无响应/RST/重置/503/429状态码


@dataclass
class RateLimitConfig:
    """速率限制配置
    核心原则：不拦截就猛爆破，拦截了才降速，恢复后快速提速
    """
    min_delay: float = 0.01       # 最小请求间隔(秒)——极限速度
    max_delay: float = 10.0       # 最大请求间隔(秒)
    initial_delay: float = 0.05   # 初始间隔(直接高速启动)
    min_threads: int = 5          # 最小并发线程数
    max_threads: int = 200        # 最大并发线程数
    initial_threads: int = 50     # 初始并发数(直接50线程起步)
    window_size: int = 20         # 统计滑动窗口大小(最近N个请求)
    cool_down_factor: float = 1.5 # 降速时的乘数因子
    speed_up_factor: float = 0.7  # 提速时的乘数因子(快速降到最小延迟)
    thread_adjust_interval: int = 5   # 每5个请求评估一次（更频繁调整）
    block_threshold: float = 0.10 # 拦截率阈值，超过10%开始降速
    success_threshold: float = 0.80    # 成功率阈值（降低门槛，更容易提速）


class AdaptiveRateLimiter:
    """
    闭环自适应速率控制器 v3.0
    
    工作原理：
    1. 滑动窗口实时统计五类连接状态占比
    2. 默认高速启动，根据拦截率自动调整
    3. 拦截率升高 → 增加间隔 + 减少并发（快速降速避免被封）
    4. 成功率稳定 → 减少间隔 + 增加并发（逐步提速提高效率）
    5. 全程无需人工干预参数，自动寻找最优平衡点
    """
    
    # 预设模式
    PRESETS = {
        "fast": RateLimitConfig(
            min_delay=0.005,          # 极限速度
            max_delay=3.0,
            initial_delay=0.02,       # 几乎不等
            initial_threads=80,       # 80线程起步
            max_threads=300,          # 最多300线程
            window_size=15,
            cool_down_factor=1.3,
            block_threshold=0.08,
            thread_adjust_interval=3,
        ),
        "normal": RateLimitConfig(),  # 默认就是normal（已优化为高速）
        "safe": RateLimitConfig(
            min_delay=0.05,
            max_delay=20.0,
            initial_delay=0.2,
            initial_threads=20,
            max_threads=50,
            window_size=40,
            cool_down_factor=2.0,
            block_threshold=0.05,
        )
    }
    
    def __init__(self, config: Optional[RateLimitConfig] = None, preset: str = "normal"):
        if config:
            self.config = config
        elif preset in self.PRESETS:
            self.config = self.PRESETS[preset]
        else:
            self.config = RateLimitConfig()
            
        self._lock = threading.RLock()
        
        # 当前状态
        self.current_delay = self.config.initial_delay
        self.current_threads = self.config.initial_threads
        
        # 滑动窗口统计
        self.state_window: Deque[ConnectionState] = deque(maxlen=self.config.window_size)
        self.request_count = 0
        self.last_adjust_time = time.time()
        
        # 统计计数
        self.stats: Dict[ConnectionState, int] = {
            state: 0 for state in ConnectionState
        }
        
        # 冷却状态标记
        self._in_cooldown = False
        self._cooldown_until = 0

    def _get_block_rate(self) -> float:
        """计算当前窗口内的拦截率
        注意：只统计真正的封禁行为（429/Connection Refused/Reset）。
        超时不算拦截——目标慢≠被封，把超时算拦截会导致疯狂降速且无法恢复。
        """
        if len(self.state_window) < 3:
            return 0.0
        # 只有CONN_REFUSED才是真正的IP封禁/拦截
        blocked = sum(1 for s in self.state_window if s == ConnectionState.CONN_REFUSED)
        return blocked / len(self.state_window)

    def _get_timeout_rate(self) -> float:
        """计算超时率（单独统计，用于辅助判断但不触发紧急降速）"""
        if len(self.state_window) < 3:
            return 0.0
        return sum(1 for s in self.state_window if s == ConnectionState.TIMEOUT) / len(self.state_window)

    def _get_success_rate(self) -> float:
        """计算当前窗口内的有效成功率（成功+正常认证失败，说明服务正常响应）"""
        if len(self.state_window) < 8:
            return 1.0
        valid_states = {ConnectionState.SUCCESS, ConnectionState.AUTH_FAIL}
        valid = sum(1 for s in self.state_window if s in valid_states)
        return valid / len(self.state_window)

    def record_state(self, state: ConnectionState):
        """记录一次请求的连接状态，用于统计调速"""
        with self._lock:
            self.state_window.append(state)
            self.stats[state] += 1
            self.request_count += 1

            # 冷却期不调整
            now = time.time()
            if now < self._cooldown_until:
                return

            # 冷却期刚结束，清空旧窗口从新统计，避免旧拦截记录拖累恢复
            if self._in_cooldown:
                self._in_cooldown = False
                self.state_window.clear()

            block_rate = self._get_block_rate()
            success_rate = self._get_success_rate()

            # 快速响应：拦截率过高立即降速
            if block_rate > self.config.block_threshold:
                self._emergency_slowdown(block_rate)
                return

            # 正常调整周期：每thread_adjust_interval个请求评估一次
            if self.request_count % self.config.thread_adjust_interval != 0:
                return

            self._adjust_parameters(block_rate, success_rate)

    def _emergency_slowdown(self, block_rate: float):
        """紧急降速：只有真正被封（429/Connection Refused）才触发
        温和降速：延迟×1.3，线程×0.75，不要砍半导致雪崩
        """
        with self._lock:
            # 延迟温和增长
            self.current_delay = min(
                self.current_delay * 1.3,
                self.config.max_delay
            )
            # 并发只减1/4，不要砍半
            self.current_threads = max(
                int(self.current_threads * 0.75),
                self.config.min_threads
            )
            # 冷却期短一些，2-5秒足够，长了影响恢复
            cooldown_time = min(5, 2 + int(block_rate * 10))
            self._cooldown_until = time.time() + cooldown_time
            self._in_cooldown = True

    def _adjust_parameters(self, block_rate: float, success_rate: float):
        """根据统计结果平滑调整速率参数
        核心原则：不拦截就猛爆破，拦截了才降速，恢复后快速提速
        """
        with self._lock:
            timeout_rate = self._get_timeout_rate()

            # 没有真正的拦截（429/Refused），就猛猛提速——超时不算拦截
            if block_rate < 0.05:
                # 延迟快速降到最小（×0.7，2-3次调整就到极限速度）
                self.current_delay = max(
                    self.current_delay * self.config.speed_up_factor,
                    self.config.min_delay
                )
                # 并发数猛增，每次+5~20，快速冲到最大并发
                add_threads = min(20, max(5, int(self.current_threads * 0.2)))
                self.current_threads = min(
                    self.current_threads + add_threads,
                    self.config.max_threads
                )
            # 超时率非常高（>60%），说明目标太慢，适当降低并发避免堆积
            elif timeout_rate > 0.6:
                self.current_threads = max(
                    self.current_threads - 5,
                    self.config.min_threads
                )
                # 但不增加延迟——超时不是被拦，不需要慢下来

    def wait(self):
        """请求前等待，控制单请求间隔
        多线程下总QPS ≈ current_threads / current_delay
        不做线程分摊——分摊公式在线程减少时会放大降速效果，导致雪崩
        """
        with self._lock:
            delay = self.current_delay
        if delay > 0:
            time.sleep(delay)

    def get_optimal_threads(self) -> int:
        """获取当前推荐的并发线程数"""
        with self._lock:
            return self.current_threads

    def get_current_delay(self) -> float:
        """获取当前请求间隔"""
        with self._lock:
            return self.current_delay

    def get_stats(self) -> Dict:
        """获取统计信息"""
        with self._lock:
            total = sum(self.stats.values()) or 1
            qps = self.current_threads / max(self.current_delay, 0.001)
            return {
                "total_requests": self.request_count,
                "current_delay": round(self.current_delay, 3),
                "current_threads": self.current_threads,
                "estimated_qps": round(qps, 1),
                "window_size": len(self.state_window),
                "block_rate": round(self._get_block_rate(), 3),
                "success_rate": round(self._get_success_rate(), 3),
                "in_cooldown": self._in_cooldown and time.time() < self._cooldown_until,
                "stats": {
                    "success": self.stats[ConnectionState.SUCCESS],
                    "auth_fail": self.stats[ConnectionState.AUTH_FAIL],
                    "conn_refused": self.stats[ConnectionState.CONN_REFUSED],
                    "timeout": self.stats[ConnectionState.TIMEOUT],
                    "no_response": self.stats[ConnectionState.NO_RESPONSE],
                }
            }

    def reset(self):
        """重置统计状态（切换目标时使用）"""
        with self._lock:
            self.current_delay = self.config.initial_delay
            self.current_threads = self.config.initial_threads
            self.state_window.clear()
            self.request_count = 0
            self.stats = {state: 0 for state in ConnectionState}
            self._in_cooldown = False
            self._cooldown_until = 0


class SimpleRateLimiter:
    """简单固定间隔限速器（兼容旧接口）"""
    
    def __init__(self, min_delay: float = 0.05, max_delay: float = 10.0, initial_delay: float = 0.1):
        self.config = RateLimitConfig(
            min_delay=min_delay,
            max_delay=max_delay,
            initial_delay=initial_delay
        )
        self._limiter = AdaptiveRateLimiter(self.config)
    
    def wait(self):
        self._limiter.wait()
    
    def success(self):
        self._limiter.record_state(ConnectionState.SUCCESS)
    
    def failure(self):
        self._limiter.record_state(ConnectionState.CONN_REFUSED)

    def __len__(self):
        return 1
