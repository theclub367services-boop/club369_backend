from django.core.management.base import BaseCommand
from django.utils import timezone
from core.models import UserSession, PaymentOrder, AutoPaySubscription
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Cleanup project-specific stale data (UserSession, PaymentOrder, AutoPaySubscription)'

    def handle(self, *args, **options):
        now = timezone.now()
        threshold = now - timezone.timedelta(days=7)
        
        # 1. Cleanup expired User Sessions
        try:
            expired_sessions = UserSession.objects.filter(expires_at__lt=now)
            count, _ = expired_sessions.delete()
            self.stdout.write(self.style.SUCCESS(f'Successfully deleted {count} expired user sessions'))
            if count > 0:
                logger.info(f"Cleanup: Deleted {count} expired sessions at {now}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error cleaning UserSession: {str(e)}'))
            logger.error(f"Cleanup Error (UserSession): {str(e)}")

        # 2. Cleanup incomplete PaymentOrders older than 7 days
        try:
            stale_orders = PaymentOrder.objects.filter(
                status='CREATED', 
                created_at__lt=threshold
            )
            count, _ = stale_orders.delete()
            self.stdout.write(self.style.SUCCESS(f'Successfully deleted {count} stale payment orders'))
            if count > 0:
                logger.info(f"Cleanup: Deleted {count} stale payment orders at {now}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error cleaning PaymentOrder: {str(e)}'))
            logger.error(f"Cleanup Error (PaymentOrder): {str(e)}")

        # 3. Cleanup pending AutoPaySubscriptions older than 7 days
        try:
            stale_subs = AutoPaySubscription.objects.filter(
                autopay_status='PENDING',
                created_at__lt=threshold
            )
            count, _ = stale_subs.delete()
            self.stdout.write(self.style.SUCCESS(f'Successfully deleted {count} stale autopay subscriptions'))
            if count > 0:
                logger.info(f"Cleanup: Deleted {count} stale autopay subscriptions at {now}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error cleaning AutoPaySubscription: {str(e)}'))
            logger.error(f"Cleanup Error (AutoPaySubscription): {str(e)}")
