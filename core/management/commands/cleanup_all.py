from django.core.management import call_command
from django.core.management.base import BaseCommand
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Run all project cleanup tasks in one go'

    def handle(self, *args, **options):
        self.stdout.write("Starting full system cleanup...")
        
        # 1. Django Session Table Cleanup
        try:
            self.stdout.write("Running clearsessions...")
            call_command('clearsessions')
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"clearsessions failed: {str(e)}"))

        # 2. JWT Token Blacklist Cleanup
        try:
            self.stdout.write("Running flushexpiredtokens...")
            call_command('flushexpiredtokens')
        except Exception as e:
            # This might fail if the app is not installed or table is missing
            self.stdout.write(self.style.ERROR(f"flushexpiredtokens failed: {str(e)}"))

        # 3. Custom Project Data Cleanup
        try:
            self.stdout.write("Running cleanup_stale_data...")
            call_command('cleanup_stale_data')
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"cleanup_stale_data failed: {str(e)}"))

        self.stdout.write(self.style.SUCCESS("Full system cleanup completed."))
        logger.info("Full system cleanup job executed successfully.")
