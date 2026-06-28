"""
core.config — 统一配置系统
取代散落在各文件的硬编码常量
支持 YAML 配置文件 + 环境变量覆盖 + 编程式修改
"""

import os
import json
from dataclasses import dataclass, field
from typing import Optional, Dict, List


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclass
class ScanConfig:
    """扫描引擎配置"""
    threads: int = 50
    timeout: int = 8
    verify_ssl: bool = True
    random_ua: bool = True

    subdomain_scan_enabled: bool = True
    internal_subdomain_count: int = 200

    max_dirs_per_scan: int = 5000
    wildcard_404_detect: bool = True

    rate_limit_enabled: bool = True
    rate_limit_preset: str = "normal"

    proxy_file: str = "proxies.txt"
    proxy_strategy: str = "round_robin"


@dataclass
class PathConfig:
    """路径配置——所有 IO 路径的唯一定义点"""
    base_dir: str = BASE_DIR
    scans_dir: str = field(default_factory=lambda: os.path.join(BASE_DIR, "data", "scans"))
    results_dir: str = field(default_factory=lambda: os.path.join(BASE_DIR, "data", "results"))
    reports_dir: str = field(default_factory=lambda: os.path.join(BASE_DIR, "data", "reports"))
    dicts_dir: str = field(default_factory=lambda: os.path.join(BASE_DIR, "dicts"))
    cache_dir: str = field(default_factory=lambda: os.path.join(BASE_DIR, "data", "cache"))

    def __post_init__(self):
        for d in [self.scans_dir, self.results_dir, self.reports_dir, self.dicts_dir, self.cache_dir]:
            os.makedirs(d, exist_ok=True)


@dataclass
class AppConfig:
    """应用全局配置"""
    scan: ScanConfig = field(default_factory=ScanConfig)
    paths: PathConfig = field(default_factory=PathConfig)

    @classmethod
    def from_yaml(cls, yaml_path: Optional[str] = None) -> "AppConfig":
        """从 YAML 文件加载配置（可选依赖 PyYAML）"""
        if yaml_path is None:
            yaml_path = os.path.join(BASE_DIR, "config.yaml")

        config = cls()

        if os.path.exists(yaml_path):
            try:
                import yaml
                with open(yaml_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                if data:
                    cls._apply_dict(config, data)
            except ImportError:
                pass
            except Exception:
                pass

        return config

    @classmethod
    def _apply_dict(cls, config: "AppConfig", data: dict):
        """递归应用字典配置到 dataclass"""
        if "scan" in data:
            s = data["scan"]
            if isinstance(s, dict):
                for k, v in s.items():
                    if hasattr(config.scan, k):
                        setattr(config.scan, k, v)
        if "paths" in data:
            p = data["paths"]
            if isinstance(p, dict):
                for k, v in p.items():
                    if hasattr(config.paths, k):
                        setattr(config.paths, k, v)


_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    """获取全局配置实例"""
    global _config
    if _config is None:
        _config = AppConfig()
    return _config


def init_config(yaml_path: Optional[str] = None) -> AppConfig:
    """初始化配置（可从 YAML 加载）"""
    global _config
    _config = AppConfig.from_yaml(yaml_path)
    return _config
