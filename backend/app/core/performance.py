# Performance optimization and caching system

import asyncio
import time
import json
import hashlib
import logging
from typing import Any, Dict, List, Optional, Union, Callable
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict, OrderedDict
import threading
import weakref

import redis
import aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, joinedload
from sqlalchemy.sql import Select

logger = logging.getLogger(__name__)

class MemoryCache:
    """High-performance in-memory cache with TTL support."""
    
    def __init__(self, max_size: int = 10000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict = OrderedDict()
        self._expiry: Dict[str, datetime] = {}
        self._lock = threading.RLock()
        
        # Start cleanup task
        self._cleanup_task = None
        self._start_cleanup_task()
    
    def _start_cleanup_task(self):
        """Start background cleanup task."""
        def cleanup_loop():
            while True:
                try:
                    self._cleanup_expired()
                    time.sleep(60)  # Cleanup every minute
                except Exception as e:
                    logger.error(f"Cache cleanup error: {e}")
                    time.sleep(10)
        
        self._cleanup_task = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_task.start()
    
    def _cleanup_expired(self):
        """Remove expired entries."""
        now = datetime.utcnow()
        expired_keys = []
        
        with self._lock:
            for key, expiry in self._expiry.items():
                if expiry < now:
                    expired_keys.append(key)
            
            for key in expired_keys:
                self._cache.pop(key, None)
                self._expiry.pop(key, None)
    
    def _evict_lru(self):
        """Evict least recently used items."""
        while len(self._cache) >= self.max_size:
            oldest_key = next(iter(self._cache))
            self._cache.pop(oldest_key)
            self._expiry.pop(oldest_key, None)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self._lock:
            # Check if expired
            if key in self._expiry and self._expiry[key] < datetime.utcnow():
                self._cache.pop(key, None)
                self._expiry.pop(key, None)
                return None
            
            # Get value and move to end (mark as recently used)
            if key in self._cache:
                value = self._cache.pop(key)
                self._cache[key] = value
                return value
            
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache."""
        with self._lock:
            # Remove existing entry
            if key in self._cache:
                self._cache.pop(key)
            
            # Evict if necessary
            self._evict_lru()
            
            # Add new entry
            self._cache[key] = value
            
            # Set expiry
            ttl = ttl or self.default_ttl
            self._expiry[key] = datetime.utcnow() + timedelta(seconds=ttl)
    
    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        with self._lock:
            deleted = key in self._cache
            self._cache.pop(key, None)
            self._expiry.pop(key, None)
            return deleted
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
            self._expiry.clear()
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'expired_entries': len([
                    k for k, exp in self._expiry.items()
                    if exp < datetime.utcnow()
                ])
            }

class RedisCache:
    """Redis-based distributed cache."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379", prefix: str = "ecyber:"):
        self.redis_url = redis_url
        self.prefix = prefix
        self._redis: Optional[aioredis.Redis] = None
        self._sync_redis: Optional[redis.Redis] = None
    
    async def _get_redis(self) -> aioredis.Redis:
        """Get async Redis connection."""
        if not self._redis:
            self._redis = aioredis.from_url(self.redis_url, decode_responses=True)
        return self._redis
    
    def _get_sync_redis(self) -> redis.Redis:
        """Get sync Redis connection."""
        if not self._sync_redis:
            self._sync_redis = redis.from_url(self.redis_url, decode_responses=True)
        return self._sync_redis
    
    def _make_key(self, key: str) -> str:
        """Create prefixed key."""
        return f"{self.prefix}{key}"
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from Redis."""
        try:
            redis_client = await self._get_redis()
            value = await redis_client.get(self._make_key(key))
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in Redis."""
        try:
            redis_client = await self._get_redis()
            serialized = json.dumps(value, default=str)
            if ttl:
                return await redis_client.setex(self._make_key(key), ttl, serialized)
            else:
                return await redis_client.set(self._make_key(key), serialized)
        except Exception as e:
            logger.error(f"Redis set error: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete key from Redis."""
        try:
            redis_client = await self._get_redis()
            return bool(await redis_client.delete(self._make_key(key)))
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False
    
    async def clear_pattern(self, pattern: str) -> int:
        """Clear keys matching pattern."""
        try:
            redis_client = await self._get_redis()
            keys = await redis_client.keys(self._make_key(pattern))
            if keys:
                return await redis_client.delete(*keys)
            return 0
        except Exception as e:
            logger.error(f"Redis clear pattern error: {e}")
            return 0

class CacheManager:
    """Unified cache manager with multiple backends."""
    
    def __init__(self, use_redis: bool = True, redis_url: str = "redis://localhost:6379"):
        self.memory_cache = MemoryCache()
        self.redis_cache = RedisCache(redis_url) if use_redis else None
        self.use_redis = use_redis
        
        # Cache hit/miss statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'deletes': 0,
        }
    
    async def get(self, key: str, use_memory: bool = True) -> Optional[Any]:
        """Get value from cache (memory first, then Redis)."""
        # Try memory cache first
        if use_memory:
            value = self.memory_cache.get(key)
            if value is not None:
                self.stats['hits'] += 1
                return value
        
        # Try Redis cache
        if self.redis_cache:
            value = await self.redis_cache.get(key)
            if value is not None:
                # Store in memory cache for faster access
                if use_memory:
                    self.memory_cache.set(key, value)
                self.stats['hits'] += 1
                return value
        
        self.stats['misses'] += 1
        return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None, use_memory: bool = True) -> None:
        """Set value in cache."""
        # Set in memory cache
        if use_memory:
            self.memory_cache.set(key, value, ttl)
        
        # Set in Redis cache
        if self.redis_cache:
            await self.redis_cache.set(key, value, ttl)
        
        self.stats['sets'] += 1
    
    async def delete(self, key: str) -> bool:
        """Delete key from all caches."""
        memory_deleted = self.memory_cache.delete(key)
        redis_deleted = False
        
        if self.redis_cache:
            redis_deleted = await self.redis_cache.delete(key)
        
        if memory_deleted or redis_deleted:
            self.stats['deletes'] += 1
            return True
        
        return False
    
    async def clear_pattern(self, pattern: str) -> None:
        """Clear keys matching pattern."""
        # Clear memory cache (simple implementation)
        if '*' in pattern:
            prefix = pattern.replace('*', '')
            keys_to_delete = [
                key for key in self.memory_cache._cache.keys()
                if key.startswith(prefix)
            ]
            for key in keys_to_delete:
                self.memory_cache.delete(key)
        
        # Clear Redis cache
        if self.redis_cache:
            await self.redis_cache.clear_pattern(pattern)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        hit_rate = 0
        total_requests = self.stats['hits'] + self.stats['misses']
        if total_requests > 0:
            hit_rate = self.stats['hits'] / total_requests
        
        return {
            **self.stats,
            'hit_rate': hit_rate,
            'memory_cache': self.memory_cache.stats(),
        }

# Global cache manager
cache_manager = CacheManager()

# Caching decorators
def cache_result(
    key_template: str,
    ttl: int = 3600,
    use_memory: bool = True,
    invalidate_patterns: Optional[List[str]] = None
):
    """Decorator to cache function results."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            key_args = []
            for arg in args:
                if hasattr(arg, 'id'):
                    key_args.append(str(arg.id))
                elif isinstance(arg, (str, int, float, bool)):
                    key_args.append(str(arg))
                else:
                    key_args.append(str(hash(str(arg))))
            
            for k, v in kwargs.items():
                if isinstance(v, (str, int, float, bool)):
                    key_args.append(f"{k}:{v}")
            
            cache_key = key_template.format(*key_args, **kwargs)
            
            # Try to get from cache
            cached_result = await cache_manager.get(cache_key, use_memory)
            if cached_result is not None:
                return cached_result
            
            # Execute function
            result = await func(*args, **kwargs)
            
            # Cache result
            await cache_manager.set(cache_key, result, ttl, use_memory)
            
            return result
        
        # Add cache invalidation method
        async def invalidate(*args, **kwargs):
            if invalidate_patterns:
                for pattern in invalidate_patterns:
                    await cache_manager.clear_pattern(pattern)
        
        wrapper.invalidate = invalidate
        return wrapper
    
    return decorator

# Database query optimization
class QueryOptimizer:
    """Database query optimization utilities."""
    
    @staticmethod
    def optimize_select(query: Select) -> Select:
        """Optimize SELECT query with eager loading."""
        # Add common optimizations
        return query.options(
            selectinload('*'),  # Eager load relationships
        ).execution_options(
            compiled_cache={}  # Enable query compilation cache
        )
    
    @staticmethod
    async def execute_with_cache(
        db: AsyncSession,
        query: Select,
        cache_key: str,
        ttl: int = 300
    ) -> List[Any]:
        """Execute query with caching."""
        # Try cache first
        cached_result = await cache_manager.get(cache_key)
        if cached_result is not None:
            return cached_result
        
        # Execute query
        result = await db.execute(query)
        rows = result.scalars().all()
        
        # Convert to serializable format
        serializable_rows = []
        for row in rows:
            if hasattr(row, '__dict__'):
                serializable_rows.append({
                    key: value for key, value in row.__dict__.items()
                    if not key.startswith('_')
                })
            else:
                serializable_rows.append(row)
        
        # Cache result
        await cache_manager.set(cache_key, serializable_rows, ttl)
        
        return rows
    
    @staticmethod
    def create_index_suggestions(db_stats: Dict[str, Any]) -> List[str]:
        """Create database index suggestions based on query patterns."""
        suggestions = []
        
        # Common index suggestions for security system
        common_indexes = [
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
            "CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);",
            "CREATE INDEX IF NOT EXISTS idx_security_logs_timestamp ON security_logs(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_security_logs_user_id ON security_logs(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_security_logs_event_type ON security_logs(event_type);",
            "CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address);",
            "CREATE INDEX IF NOT EXISTS idx_login_attempts_timestamp ON login_attempts(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_threat_detections_timestamp ON threat_detections(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_threat_detections_severity ON threat_detections(severity);",
            "CREATE INDEX IF NOT EXISTS idx_network_events_timestamp ON network_events(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_network_events_source_ip ON network_events(source_ip);",
        ]
        
        suggestions.extend(common_indexes)
        
        return suggestions

# Connection pooling optimization
class DatabaseOptimizer:
    """Database connection and query optimization."""
    
    def __init__(self):
        self.query_stats = defaultdict(lambda: {
            'count': 0,
            'total_time': 0,
            'avg_time': 0,
            'slow_queries': []
        })
    
    def record_query(self, query: str, execution_time: float):
        """Record query execution statistics."""
        stats = self.query_stats[query]
        stats['count'] += 1
        stats['total_time'] += execution_time
        stats['avg_time'] = stats['total_time'] / stats['count']
        
        # Track slow queries (>1 second)
        if execution_time > 1.0:
            stats['slow_queries'].append({
                'timestamp': datetime.utcnow().isoformat(),
                'execution_time': execution_time
            })
            
            # Keep only recent slow queries
            if len(stats['slow_queries']) > 10:
                stats['slow_queries'] = stats['slow_queries'][-10:]
    
    def get_slow_queries(self, min_avg_time: float = 0.5) -> List[Dict[str, Any]]:
        """Get queries with high average execution time."""
        slow_queries = []
        
        for query, stats in self.query_stats.items():
            if stats['avg_time'] > min_avg_time:
                slow_queries.append({
                    'query': query[:200] + '...' if len(query) > 200 else query,
                    'count': stats['count'],
                    'avg_time': stats['avg_time'],
                    'total_time': stats['total_time'],
                    'slow_executions': len(stats['slow_queries'])
                })
        
        return sorted(slow_queries, key=lambda x: x['avg_time'], reverse=True)
    
    async def optimize_database(self, db: AsyncSession) -> Dict[str, Any]:
        """Run database optimization tasks."""
        optimization_results = {
            'indexes_created': 0,
            'statistics_updated': False,
            'vacuum_performed': False,
            'suggestions': []
        }
        
        try:
            # Create recommended indexes
            index_suggestions = QueryOptimizer.create_index_suggestions({})
            for index_sql in index_suggestions:
                try:
                    await db.execute(text(index_sql))
                    optimization_results['indexes_created'] += 1
                except Exception as e:
                    logger.warning(f"Failed to create index: {e}")
            
            # Update table statistics (PostgreSQL)
            try:
                await db.execute(text("ANALYZE;"))
                optimization_results['statistics_updated'] = True
            except Exception as e:
                logger.warning(f"Failed to update statistics: {e}")
            
            await db.commit()
            
        except Exception as e:
            logger.error(f"Database optimization error: {e}")
            await db.rollback()
        
        return optimization_results

# Performance monitoring
class PerformanceMonitor:
    """Monitor system performance metrics."""
    
    def __init__(self):
        self.metrics = {
            'request_count': 0,
            'total_request_time': 0,
            'avg_response_time': 0,
            'error_count': 0,
            'cache_hit_rate': 0,
            'db_query_count': 0,
            'db_query_time': 0,
            'memory_usage': 0,
            'cpu_usage': 0,
        }
        
        self.request_times = []
        self.error_rates = []
        
        # Start monitoring task
        self._start_monitoring()
    
    def _start_monitoring(self):
        """Start background monitoring."""
        def monitor_loop():
            while True:
                try:
                    self._collect_system_metrics()
                    time.sleep(30)  # Collect every 30 seconds
                except Exception as e:
                    logger.error(f"Performance monitoring error: {e}")
                    time.sleep(10)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    
    def _collect_system_metrics(self):
        """Collect system performance metrics."""
        try:
            import psutil
            
            # CPU usage
            self.metrics['cpu_usage'] = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.metrics['memory_usage'] = memory.percent
            
            # Cache statistics
            cache_stats = cache_manager.get_stats()
            self.metrics['cache_hit_rate'] = cache_stats['hit_rate']
            
        except ImportError:
            # psutil not available
            pass
        except Exception as e:
            logger.error(f"System metrics collection error: {e}")
    
    def record_request(self, response_time: float, is_error: bool = False):
        """Record request metrics."""
        self.metrics['request_count'] += 1
        self.metrics['total_request_time'] += response_time
        self.metrics['avg_response_time'] = (
            self.metrics['total_request_time'] / self.metrics['request_count']
        )
        
        if is_error:
            self.metrics['error_count'] += 1
        
        # Keep recent request times for percentile calculations
        self.request_times.append(response_time)
        if len(self.request_times) > 1000:
            self.request_times = self.request_times[-1000:]
        
        # Calculate error rate
        error_rate = self.metrics['error_count'] / self.metrics['request_count']
        self.error_rates.append(error_rate)
        if len(self.error_rates) > 100:
            self.error_rates = self.error_rates[-100:]
    
    def record_db_query(self, query_time: float):
        """Record database query metrics."""
        self.metrics['db_query_count'] += 1
        self.metrics['db_query_time'] += query_time
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report."""
        # Calculate percentiles
        percentiles = {}
        if self.request_times:
            sorted_times = sorted(self.request_times)
            percentiles = {
                'p50': sorted_times[int(len(sorted_times) * 0.5)],
                'p90': sorted_times[int(len(sorted_times) * 0.9)],
                'p95': sorted_times[int(len(sorted_times) * 0.95)],
                'p99': sorted_times[int(len(sorted_times) * 0.99)],
            }
        
        return {
            'metrics': self.metrics,
            'percentiles': percentiles,
            'current_error_rate': self.error_rates[-1] if self.error_rates else 0,
            'cache_stats': cache_manager.get_stats(),
            'timestamp': datetime.utcnow().isoformat(),
        }

# Global instances
db_optimizer = DatabaseOptimizer()
performance_monitor = PerformanceMonitor()

# Performance middleware
class PerformanceMiddleware:
    """Middleware to track performance metrics."""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        start_time = time.time()
        
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                response_time = time.time() - start_time
                status_code = message["status"]
                is_error = status_code >= 400
                
                performance_monitor.record_request(response_time, is_error)
            
            await send(message)
        
        await self.app(scope, receive, send_wrapper)

# Export performance components
__all__ = [
    'MemoryCache',
    'RedisCache',
    'CacheManager',
    'cache_manager',
    'cache_result',
    'QueryOptimizer',
    'DatabaseOptimizer',
    'db_optimizer',
    'PerformanceMonitor',
    'performance_monitor',
    'PerformanceMiddleware'
]

