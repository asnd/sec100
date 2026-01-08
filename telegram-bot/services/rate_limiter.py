"""
Rate limiting service for Telegram bot.

Tracks user query rates in memory to prevent abuse and protect the database.
"""

import time
from typing import Dict, Tuple
from collections import defaultdict, deque


class RateLimiter:
    """
    In-memory rate limiter with per-user tracking.

    Tracks queries per minute and per hour for each user.
    """

    def __init__(
        self,
        max_per_minute: int = 10,
        max_per_hour: int = 50,
        admin_user_ids: list = None
    ):
        """
        Initialize rate limiter.

        Args:
            max_per_minute: Maximum queries per minute per user
            max_per_hour: Maximum queries per hour per user
            admin_user_ids: List of admin user IDs (bypass rate limits)
        """
        self.max_per_minute = max_per_minute
        self.max_per_hour = max_per_hour
        self.admin_user_ids = set(admin_user_ids or [])

        # User query timestamps: {user_id: deque(timestamps)}
        self.user_queries: Dict[int, deque] = defaultdict(lambda: deque())

    def is_admin(self, user_id: int) -> bool:
        """Check if user is an admin (bypasses rate limits)."""
        return user_id in self.admin_user_ids

    def check_rate_limit(self, user_id: int) -> Tuple[bool, str]:
        """
        Check if a user is within rate limits.

        Args:
            user_id: Telegram user ID

        Returns:
            Tuple of (allowed: bool, message: str)
            - If allowed=True, user can proceed
            - If allowed=False, message contains wait time or error
        """
        # Admins bypass rate limits
        if self.is_admin(user_id):
            return True, ""

        current_time = time.time()
        user_timestamps = self.user_queries[user_id]

        # Clean old timestamps (older than 1 hour)
        while user_timestamps and current_time - user_timestamps[0] > 3600:
            user_timestamps.popleft()

        # Count queries in last minute
        minute_ago = current_time - 60
        queries_last_minute = sum(1 for ts in user_timestamps if ts >= minute_ago)

        # Count queries in last hour
        queries_last_hour = len(user_timestamps)

        # Check minute limit
        if queries_last_minute >= self.max_per_minute:
            # Calculate wait time
            oldest_in_minute = next(ts for ts in reversed(user_timestamps) if ts >= minute_ago)
            wait_seconds = int(60 - (current_time - oldest_in_minute))

            return False, (
                f"⏱️ Rate limit: {self.max_per_minute} queries/minute exceeded.\n"
                f"Please wait {wait_seconds} seconds.\n\n"
                f"Your usage: {queries_last_minute} queries in last minute, "
                f"{queries_last_hour} queries in last hour."
            )

        # Check hour limit
        if queries_last_hour >= self.max_per_hour:
            # Calculate wait time
            oldest_timestamp = user_timestamps[0]
            wait_seconds = int(3600 - (current_time - oldest_timestamp))
            wait_minutes = wait_seconds // 60

            return False, (
                f"⏱️ Rate limit: {self.max_per_hour} queries/hour exceeded.\n"
                f"Please wait {wait_minutes} minutes.\n\n"
                f"Your usage: {queries_last_hour} queries in last hour."
            )

        # Within limits
        return True, ""

    def record_query(self, user_id: int) -> None:
        """
        Record a query for rate limiting.

        Args:
            user_id: Telegram user ID
        """
        if self.is_admin(user_id):
            # Still record for stats, but don't enforce limits
            pass

        self.user_queries[user_id].append(time.time())

    def get_user_stats(self, user_id: int) -> Dict:
        """
        Get query statistics for a user.

        Args:
            user_id: Telegram user ID

        Returns:
            Dictionary with:
            - queries_last_minute: int
            - queries_last_hour: int
            - is_admin: bool
        """
        current_time = time.time()
        user_timestamps = self.user_queries.get(user_id, deque())

        minute_ago = current_time - 60
        hour_ago = current_time - 3600

        queries_last_minute = sum(1 for ts in user_timestamps if ts >= minute_ago)
        queries_last_hour = sum(1 for ts in user_timestamps if ts >= hour_ago)

        return {
            "queries_last_minute": queries_last_minute,
            "queries_last_hour": queries_last_hour,
            "is_admin": self.is_admin(user_id)
        }

    def reset_user(self, user_id: int) -> None:
        """
        Reset rate limit tracking for a user.

        Args:
            user_id: Telegram user ID
        """
        if user_id in self.user_queries:
            del self.user_queries[user_id]

    def get_global_stats(self) -> Dict:
        """
        Get global rate limiter statistics.

        Returns:
            Dictionary with:
            - total_users: int
            - total_queries_last_hour: int
        """
        current_time = time.time()
        hour_ago = current_time - 3600

        total_users = len(self.user_queries)
        total_queries = 0

        for timestamps in self.user_queries.values():
            total_queries += sum(1 for ts in timestamps if ts >= hour_ago)

        return {
            "total_users": total_users,
            "total_queries_last_hour": total_queries
        }
