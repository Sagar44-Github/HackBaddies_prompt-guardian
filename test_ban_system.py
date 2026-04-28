#!/usr/bin/env python3
"""
test_ban_system.py — Test the Temporary User Ban Feature

This script tests the ban system functionality including:
- Violation tracking
- Automatic ban enforcement
- Ban status checking
- Manual ban/unban operations
"""

import sys
import time
import logging
from firewall.user_ban import UserBanManager

# Configure logging for tests
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("test-ban-system")


def test_violation_tracking():
    """Test basic violation tracking and automatic ban enforcement."""
    print("\n=== Testing Violation Tracking ===")
    
    # Create ban manager with low thresholds for testing
    ban_manager = UserBanManager(max_warnings=2, max_blocks=2, ban_duration_days=1)
    test_user = "test_user_1"
    
    # Test warning tracking
    print(f"User {test_user}: 1st warning")
    was_banned, duration = ban_manager.record_violation(test_user, "WARN")
    assert not was_banned, "Should not be banned after 1 warning"
    
    print(f"User {test_user}: 2nd warning (should trigger ban)")
    was_banned, duration = ban_manager.record_violation(test_user, "WARN")
    assert was_banned, "Should be banned after 2 warnings"
    assert duration == 86400, "Ban duration should be 1 day (86400 seconds)"
    
    # Check ban status
    is_banned, remaining = ban_manager.is_banned(test_user)
    assert is_banned, "User should still be banned"
    assert remaining > 0, "Should have remaining ban time"
    
    print(f"✓ User banned successfully. Remaining time: {remaining}s")
    
    # Test block tracking
    test_user_2 = "test_user_2"
    print(f"\nUser {test_user_2}: 1st block")
    was_banned, duration = ban_manager.record_violation(test_user_2, "BLOCK")
    assert not was_banned, "Should not be banned after 1 block"
    
    print(f"User {test_user_2}: 2nd block (should trigger ban)")
    was_banned, duration = ban_manager.record_violation(test_user_2, "BLOCK")
    assert was_banned, "Should be banned after 2 blocks"
    
    print(f"✓ User banned successfully via blocks")


def test_ban_expiry():
    """Test that bans expire correctly."""
    print("\n=== Testing Ban Expiry ===")
    
    # Create ban manager with very short ban duration for testing
    ban_manager = UserBanManager(max_warnings=1, max_blocks=1, ban_duration_days=0)
    test_user = "test_user_expiry"
    
    # Ban the user
    print(f"Banning user {test_user} for 0 days (should expire immediately)")
    was_banned, duration = ban_manager.record_violation(test_user, "WARN")
    assert was_banned, "User should be banned"
    
    # Wait a moment and check if expired
    time.sleep(0.1)
    
    is_banned, remaining = ban_manager.is_banned(test_user)
    assert not is_banned, "Ban should have expired"
    assert remaining is None, "No remaining time should be reported"
    
    # Check that counters were reset
    status = ban_manager.get_user_status(test_user)
    assert status["warning_count"] == 0, "Warning count should be reset"
    assert status["block_count"] == 0, "Block count should be reset"
    
    print("✓ Ban expiry and counter reset working correctly")


def test_manual_ban_operations():
    """Test manual ban and unban operations."""
    print("\n=== Testing Manual Ban Operations ===")
    
    ban_manager = UserBanManager(max_warnings=5, max_blocks=5, ban_duration_days=7)
    test_user = "test_user_manual"
    
    # Test manual ban
    print(f"Manually banning user {test_user}")
    success = ban_manager.manually_ban_user(test_user)
    assert success, "Manual ban should succeed"
    
    is_banned, remaining = ban_manager.is_banned(test_user)
    assert is_banned, "User should be banned"
    assert remaining > 0, "Should have remaining ban time"
    
    # Test trying to ban already banned user
    print("Attempting to ban already banned user")
    success = ban_manager.manually_ban_user(test_user)
    assert not success, "Should not be able to ban already banned user"
    
    # Test manual unban
    print(f"Manually unbanning user {test_user}")
    success = ban_manager.unban_user(test_user)
    assert success, "Manual unban should succeed"
    
    is_banned, remaining = ban_manager.is_banned(test_user)
    assert not is_banned, "User should no longer be banned"
    
    # Test trying to unban non-banned user
    print("Attempting to unban non-banned user")
    success = ban_manager.unban_user(test_user)
    assert not success, "Should not be able to unban non-banned user"
    
    print("✓ Manual ban/unban operations working correctly")


def test_user_status():
    """Test user status reporting."""
    print("\n=== Testing User Status ===")
    
    ban_manager = UserBanManager(max_warnings=3, max_blocks=3, ban_duration_days=2)
    test_user = "test_user_status"
    
    # Get initial status
    status = ban_manager.get_user_status(test_user)
    assert status["user_id"] == test_user
    assert status["warning_count"] == 0
    assert status["block_count"] == 0
    assert not status["is_banned"]
    assert status["ban_remaining_seconds"] is None
    
    # Add some violations
    ban_manager.record_violation(test_user, "WARN")
    ban_manager.record_violation(test_user, "BLOCK")
    
    status = ban_manager.get_user_status(test_user)
    assert status["warning_count"] == 1
    assert status["block_count"] == 1
    assert not status["is_banned"]
    
    print(f"✓ User status: {status['warning_count']} warnings, {status['block_count']} blocks")


def test_admin_summary():
    """Test admin summary statistics."""
    print("\n=== Testing Admin Summary ===")
    
    ban_manager = UserBanManager(max_warnings=2, max_blocks=2, ban_duration_days=1)
    
    # Create multiple users with different violation levels
    users = ["user1", "user2", "user3", "user4"]
    
    # user1: 1 warning
    ban_manager.record_violation(users[0], "WARN")
    
    # user2: 2 warnings (banned)
    ban_manager.record_violation(users[1], "WARN")
    ban_manager.record_violation(users[1], "WARN")
    
    # user3: 1 block
    ban_manager.record_violation(users[2], "BLOCK")
    
    # user4: 2 blocks (banned)
    ban_manager.record_violation(users[3], "BLOCK")
    ban_manager.record_violation(users[3], "BLOCK")
    
    # Get summary
    summary = ban_manager.get_all_users_summary()
    
    assert summary["total_users"] == 4
    assert summary["active_bans"] == 2
    assert summary["total_warnings"] == 3
    assert summary["total_blocks"] == 3
    assert summary["max_warnings"] == 2
    assert summary["max_blocks"] == 2
    assert summary["ban_duration_days"] == 1
    
    print(f"✓ Admin summary: {summary['total_users']} users, {summary['active_bans']} active bans")


def run_all_tests():
    """Run all ban system tests."""
    print("Starting Ban System Tests...")
    print("=" * 50)
    
    try:
        test_violation_tracking()
        test_ban_expiry()
        test_manual_ban_operations()
        test_user_status()
        test_admin_summary()
        
        print("\n" + "=" * 50)
        print("✅ ALL TESTS PASSED!")
        print("Ban system is working correctly.")
        return True
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return False
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
