"""
APILeak Monitoring System
Advanced monitoring, metrics collection, and anomaly detection
"""

import asyncio
import time
import threading
import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from collections import deque, defaultdict
from pathlib import Path
import logging
import logging.handlers
from enum import Enum

from .logging import get_logger


class AlertLevel(str, Enum):
    """Alert severity levels"""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class MetricType(str, Enum):
    """Types of metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class Alert:
    """System alert representation"""
    id: str
    timestamp: datetime
    level: AlertLevel
    category: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolved_at: Optional[datetime] = None


@dataclass
class Metric:
    """System metric representation"""
    name: str
    type: MetricType
    value: float
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    unit: Optional[str] = None


@dataclass
class PerformanceSnapshot:
    """Performance metrics snapshot"""
    timestamp: datetime
    response_time_avg: float
    response_time_p95: float
    response_time_p99: float
    success_rate: float
    requests_per_second: float
    error_rate: float
    memory_usage_mb: float
    active_connections: int
    rate_limited_requests: int


@dataclass
class AnomalyThresholds:
    """Thresholds for anomaly detection"""
    max_response_time: float = 30.0  # seconds
    min_success_rate: float = 0.8  # 80%
    max_error_rate: float = 0.2  # 20%
    max_memory_usage_mb: float = 512.0  # MB
    max_consecutive_timeouts: int = 5
    max_consecutive_rate_limits: int = 3


class LogRotationHandler:
    """
    Advanced log rotation handler with size and time-based rotation
    """
    
    def __init__(self, log_dir: str = "logs", max_size_mb: int = 100, max_files: int = 10):
        """
        Initialize log rotation handler
        
        Args:
            log_dir: Directory for log files
            max_size_mb: Maximum size per log file in MB
            max_files: Maximum number of log files to keep
        """
        self.log_dir = Path(log_dir)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_files = max_files
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup rotating file handler
        self.setup_rotation()
    
    def setup_rotation(self):
        """Setup log rotation with size and time-based rotation"""
        log_file = self.log_dir / "apileak.log"
        
        # Size-based rotation
        size_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self.max_size_bytes,
            backupCount=self.max_files
        )
        
        # Time-based rotation (daily)
        time_handler = logging.handlers.TimedRotatingFileHandler(
            self.log_dir / "apileak_daily.log",
            when='midnight',
            interval=1,
            backupCount=30  # Keep 30 days
        )
        
        # Configure formatters
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        size_handler.setFormatter(formatter)
        time_handler.setFormatter(formatter)
        
        # Add handlers to root logger
        logger = logging.getLogger()
        logger.addHandler(size_handler)
        logger.addHandler(time_handler)
    
    def cleanup_old_logs(self):
        """Clean up old log files beyond retention period"""
        try:
            log_files = list(self.log_dir.glob("*.log*"))
            # Sort by modification time
            log_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Keep only the most recent files
            for log_file in log_files[self.max_files:]:
                log_file.unlink()
                
        except Exception as e:
            logging.error(f"Error cleaning up old logs: {e}")


class PerformanceMonitor:
    """
    Performance monitoring and metrics collection
    """
    
    def __init__(self, window_size: int = 1000):
        """
        Initialize performance monitor
        
        Args:
            window_size: Size of sliding window for metrics
        """
        self.window_size = window_size
        self.response_times = deque(maxlen=window_size)
        self.request_results = deque(maxlen=window_size)  # True for success, False for error
        self.request_timestamps = deque(maxlen=window_size)
        self.memory_usage = deque(maxlen=window_size)
        self.active_connections = 0
        self.rate_limited_requests = 0
        self.total_requests = 0
        self.total_errors = 0
        
        self.logger = get_logger("performance_monitor")
    
    def record_request(self, response_time: float, success: bool, memory_mb: float = 0):
        """
        Record a request's performance metrics
        
        Args:
            response_time: Response time in seconds
            success: Whether the request was successful
            memory_mb: Current memory usage in MB
        """
        now = datetime.now()
        
        self.response_times.append(response_time)
        self.request_results.append(success)
        self.request_timestamps.append(now)
        if memory_mb > 0:
            self.memory_usage.append(memory_mb)
        
        self.total_requests += 1
        if not success:
            self.total_errors += 1
    
    def get_performance_snapshot(self) -> PerformanceSnapshot:
        """Get current performance metrics snapshot"""
        if not self.response_times:
            return PerformanceSnapshot(
                timestamp=datetime.now(),
                response_time_avg=0.0,
                response_time_p95=0.0,
                response_time_p99=0.0,
                success_rate=1.0,
                requests_per_second=0.0,
                error_rate=0.0,
                memory_usage_mb=0.0,
                active_connections=self.active_connections,
                rate_limited_requests=self.rate_limited_requests
            )
        
        # Calculate response time metrics
        sorted_times = sorted(self.response_times)
        avg_time = sum(sorted_times) / len(sorted_times)
        p95_time = sorted_times[int(len(sorted_times) * 0.95)] if sorted_times else 0
        p99_time = sorted_times[int(len(sorted_times) * 0.99)] if sorted_times else 0
        
        # Calculate success rate
        success_count = sum(1 for result in self.request_results if result)
        success_rate = success_count / len(self.request_results) if self.request_results else 1.0
        error_rate = 1.0 - success_rate
        
        # Calculate requests per second (last minute)
        now = datetime.now()
        recent_requests = [
            ts for ts in self.request_timestamps 
            if (now - ts).total_seconds() <= 60
        ]
        requests_per_second = len(recent_requests) / 60.0
        
        # Get current memory usage
        current_memory = self.memory_usage[-1] if self.memory_usage else 0.0
        
        return PerformanceSnapshot(
            timestamp=now,
            response_time_avg=avg_time,
            response_time_p95=p95_time,
            response_time_p99=p99_time,
            success_rate=success_rate,
            requests_per_second=requests_per_second,
            error_rate=error_rate,
            memory_usage_mb=current_memory,
            active_connections=self.active_connections,
            rate_limited_requests=self.rate_limited_requests
        )
    
    def increment_active_connections(self):
        """Increment active connections counter"""
        self.active_connections += 1
    
    def decrement_active_connections(self):
        """Decrement active connections counter"""
        self.active_connections = max(0, self.active_connections - 1)
    
    def increment_rate_limited(self):
        """Increment rate limited requests counter"""
        self.rate_limited_requests += 1


class AnomalyDetector:
    """
    Anomaly detection and alerting system
    """
    
    def __init__(self, thresholds: AnomalyThresholds = None):
        """
        Initialize anomaly detector
        
        Args:
            thresholds: Anomaly detection thresholds
        """
        self.thresholds = thresholds or AnomalyThresholds()
        self.consecutive_timeouts = 0
        self.consecutive_rate_limits = 0
        self.alerts: List[Alert] = []
        self.alert_callbacks: List[Callable[[Alert], None]] = []
        
        self.logger = get_logger("anomaly_detector")
    
    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """Add callback function for alert notifications"""
        self.alert_callbacks.append(callback)
    
    def check_anomalies(self, snapshot: PerformanceSnapshot) -> List[Alert]:
        """
        Check for anomalies in performance snapshot
        
        Args:
            snapshot: Performance metrics snapshot
            
        Returns:
            List of detected alerts
        """
        alerts = []
        
        # Check response time anomaly
        if snapshot.response_time_avg > self.thresholds.max_response_time:
            alert = Alert(
                id=f"high_response_time_{int(time.time())}",
                timestamp=snapshot.timestamp,
                level=AlertLevel.WARNING,
                category="performance",
                message=f"High average response time: {snapshot.response_time_avg:.2f}s",
                details={
                    "avg_response_time": snapshot.response_time_avg,
                    "threshold": self.thresholds.max_response_time,
                    "p95_response_time": snapshot.response_time_p95,
                    "p99_response_time": snapshot.response_time_p99
                }
            )
            alerts.append(alert)
        
        # Check success rate anomaly
        if snapshot.success_rate < self.thresholds.min_success_rate:
            alert = Alert(
                id=f"low_success_rate_{int(time.time())}",
                timestamp=snapshot.timestamp,
                level=AlertLevel.ERROR,
                category="reliability",
                message=f"Low success rate: {snapshot.success_rate:.2%}",
                details={
                    "success_rate": snapshot.success_rate,
                    "threshold": self.thresholds.min_success_rate,
                    "error_rate": snapshot.error_rate
                }
            )
            alerts.append(alert)
        
        # Check error rate anomaly
        if snapshot.error_rate > self.thresholds.max_error_rate:
            alert = Alert(
                id=f"high_error_rate_{int(time.time())}",
                timestamp=snapshot.timestamp,
                level=AlertLevel.ERROR,
                category="reliability",
                message=f"High error rate: {snapshot.error_rate:.2%}",
                details={
                    "error_rate": snapshot.error_rate,
                    "threshold": self.thresholds.max_error_rate,
                    "success_rate": snapshot.success_rate
                }
            )
            alerts.append(alert)
        
        # Check memory usage anomaly
        if snapshot.memory_usage_mb > self.thresholds.max_memory_usage_mb:
            alert = Alert(
                id=f"high_memory_usage_{int(time.time())}",
                timestamp=snapshot.timestamp,
                level=AlertLevel.WARNING,
                category="resource",
                message=f"High memory usage: {snapshot.memory_usage_mb:.1f}MB",
                details={
                    "memory_usage_mb": snapshot.memory_usage_mb,
                    "threshold": self.thresholds.max_memory_usage_mb
                }
            )
            alerts.append(alert)
        
        # Check rate limiting anomaly
        if snapshot.rate_limited_requests > 0:
            self.consecutive_rate_limits += 1
            if self.consecutive_rate_limits >= self.thresholds.max_consecutive_rate_limits:
                alert = Alert(
                    id=f"consecutive_rate_limits_{int(time.time())}",
                    timestamp=snapshot.timestamp,
                    level=AlertLevel.WARNING,
                    category="rate_limiting",
                    message=f"Consecutive rate limiting detected: {self.consecutive_rate_limits} times",
                    details={
                        "consecutive_count": self.consecutive_rate_limits,
                        "threshold": self.thresholds.max_consecutive_rate_limits,
                        "rate_limited_requests": snapshot.rate_limited_requests
                    }
                )
                alerts.append(alert)
        else:
            self.consecutive_rate_limits = 0
        
        # Store alerts and trigger callbacks
        for alert in alerts:
            self.alerts.append(alert)
            self.logger.warning(
                "Anomaly detected",
                alert_id=alert.id,
                level=alert.level,
                category=alert.category,
                message=alert.message,
                details=alert.details
            )
            
            # Trigger alert callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    self.logger.error(f"Error in alert callback: {e}")
        
        return alerts
    
    def record_timeout(self):
        """Record a timeout event"""
        self.consecutive_timeouts += 1
        if self.consecutive_timeouts >= self.thresholds.max_consecutive_timeouts:
            alert = Alert(
                id=f"consecutive_timeouts_{int(time.time())}",
                timestamp=datetime.now(),
                level=AlertLevel.ERROR,
                category="connectivity",
                message=f"Consecutive timeouts detected: {self.consecutive_timeouts} times",
                details={
                    "consecutive_count": self.consecutive_timeouts,
                    "threshold": self.thresholds.max_consecutive_timeouts
                }
            )
            self.alerts.append(alert)
            
            # Trigger callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    self.logger.error(f"Error in timeout alert callback: {e}")
    
    def record_success(self):
        """Record a successful request (resets timeout counter)"""
        self.consecutive_timeouts = 0
    
    def get_active_alerts(self) -> List[Alert]:
        """Get list of active (unresolved) alerts"""
        return [alert for alert in self.alerts if not alert.resolved]
    
    def resolve_alert(self, alert_id: str):
        """Mark an alert as resolved"""
        for alert in self.alerts:
            if alert.id == alert_id and not alert.resolved:
                alert.resolved = True
                alert.resolved_at = datetime.now()
                self.logger.info(f"Alert resolved: {alert_id}")
                break


class MonitoringSystem:
    """
    Main monitoring system that coordinates all monitoring components
    """
    
    def __init__(self, 
                 log_dir: str = "logs",
                 max_log_size_mb: int = 100,
                 max_log_files: int = 10,
                 thresholds: AnomalyThresholds = None,
                 metrics_window_size: int = 1000):
        """
        Initialize monitoring system
        
        Args:
            log_dir: Directory for log files
            max_log_size_mb: Maximum size per log file in MB
            max_log_files: Maximum number of log files to keep
            thresholds: Anomaly detection thresholds
            metrics_window_size: Size of metrics sliding window
        """
        self.log_rotation = LogRotationHandler(log_dir, max_log_size_mb, max_log_files)
        self.performance_monitor = PerformanceMonitor(metrics_window_size)
        self.anomaly_detector = AnomalyDetector(thresholds)
        
        self.monitoring_active = False
        self.monitoring_thread = None
        self.monitoring_interval = 30  # seconds
        
        self.logger = get_logger("monitoring_system")
        
        # Setup default alert callback
        self.anomaly_detector.add_alert_callback(self._default_alert_handler)
    
    def _default_alert_handler(self, alert: Alert):
        """Default alert handler that logs alerts"""
        self.logger.error(
            f"ALERT: {alert.message}",
            alert_id=alert.id,
            level=alert.level.value,
            category=alert.category,
            details=alert.details
        )
    
    def start_monitoring(self):
        """Start background monitoring thread"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        self.logger.info("Monitoring system started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        self.logger.info("Monitoring system stopped")
    
    def _monitoring_loop(self):
        """Background monitoring loop"""
        while self.monitoring_active:
            try:
                # Get performance snapshot
                snapshot = self.performance_monitor.get_performance_snapshot()
                
                # Check for anomalies
                alerts = self.anomaly_detector.check_anomalies(snapshot)
                
                # Log performance metrics
                self.logger.info(
                    "Performance metrics",
                    avg_response_time=snapshot.response_time_avg,
                    p95_response_time=snapshot.response_time_p95,
                    success_rate=snapshot.success_rate,
                    requests_per_second=snapshot.requests_per_second,
                    error_rate=snapshot.error_rate,
                    memory_usage_mb=snapshot.memory_usage_mb,
                    active_connections=snapshot.active_connections,
                    rate_limited_requests=snapshot.rate_limited_requests,
                    alerts_count=len(alerts)
                )
                
                # Clean up old logs periodically
                if int(time.time()) % 3600 == 0:  # Every hour
                    self.log_rotation.cleanup_old_logs()
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}", exc_info=True)
            
            time.sleep(self.monitoring_interval)
    
    def record_request(self, response_time: float, success: bool, memory_mb: float = 0):
        """Record request metrics"""
        self.performance_monitor.record_request(response_time, success, memory_mb)
        
        if success:
            self.anomaly_detector.record_success()
    
    def record_timeout(self):
        """Record timeout event"""
        self.anomaly_detector.record_timeout()
    
    def record_rate_limit(self):
        """Record rate limiting event"""
        self.performance_monitor.increment_rate_limited()
    
    def increment_connections(self):
        """Increment active connections"""
        self.performance_monitor.increment_active_connections()
    
    def decrement_connections(self):
        """Decrement active connections"""
        self.performance_monitor.decrement_active_connections()
    
    def get_performance_snapshot(self) -> PerformanceSnapshot:
        """Get current performance snapshot"""
        return self.performance_monitor.get_performance_snapshot()
    
    def get_active_alerts(self) -> List[Alert]:
        """Get active alerts"""
        return self.anomaly_detector.get_active_alerts()
    
    def resolve_alert(self, alert_id: str):
        """Resolve an alert"""
        self.anomaly_detector.resolve_alert(alert_id)
    
    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """Add custom alert callback"""
        self.anomaly_detector.add_alert_callback(callback)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary"""
        snapshot = self.get_performance_snapshot()
        active_alerts = self.get_active_alerts()
        
        return {
            "timestamp": snapshot.timestamp.isoformat(),
            "performance": {
                "response_time_avg": snapshot.response_time_avg,
                "response_time_p95": snapshot.response_time_p95,
                "response_time_p99": snapshot.response_time_p99,
                "success_rate": snapshot.success_rate,
                "error_rate": snapshot.error_rate,
                "requests_per_second": snapshot.requests_per_second,
                "memory_usage_mb": snapshot.memory_usage_mb,
                "active_connections": snapshot.active_connections,
                "rate_limited_requests": snapshot.rate_limited_requests
            },
            "alerts": {
                "active_count": len(active_alerts),
                "alerts": [
                    {
                        "id": alert.id,
                        "level": alert.level.value,
                        "category": alert.category,
                        "message": alert.message,
                        "timestamp": alert.timestamp.isoformat()
                    }
                    for alert in active_alerts
                ]
            },
            "system": {
                "monitoring_active": self.monitoring_active,
                "total_requests": self.performance_monitor.total_requests,
                "total_errors": self.performance_monitor.total_errors
            }
        }