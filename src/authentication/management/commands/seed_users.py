"""
Django management command to seed fake users for development/testing
Usage: python manage.py seed_users
"""
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import transaction
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Seeds the database with fake users for development/testing'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing users before seeding',
        )

    def handle(self, *args, **options):
        # Check if users already exist
        existing_count = User.objects.count()
        
        if existing_count > 0 and not options['clear']:
            self.stdout.write(
                self.style.WARNING(
                    f'Database already contains {existing_count} users. '
                    'Use --clear flag to remove them first.'
                )
            )
            return

        if options['clear']:
            self.stdout.write('Clearing existing users...')
            User.objects.all().delete()
            self.stdout.write(self.style.SUCCESS('Users cleared.'))

        self.stdout.write('Seeding fake users...')
        
        fake_users = [
            {
                'username': 'admin',
                'email': 'admin@medinsights.com',
                'password': 'Admin123!',
                'role': 'admin',
                'is_staff': True,
                'is_superuser': True,
                'is_active': True,
                'email_verified': True,
            },
            {
                'username': 'doctor1',
                'email': 'doctor1@medinsights.com',
                'password': 'Doctor123!',
                'role': 'doctor',
                'is_staff': False,
                'is_superuser': False,
                'is_active': True,
                'email_verified': True,
            },
            {
                'username': 'doctor2',
                'email': 'doctor2@medinsights.com',
                'password': 'Doctor123!',
                'role': 'doctor',
                'is_staff': False,
                'is_superuser': False,
                'is_active': True,
                'email_verified': True,
            },
            {
                'username': 'nurse1',
                'email': 'nurse1@medinsights.com',
                'password': 'Nurse123!',
                'role': 'secretary',
                'is_staff': False,
                'is_superuser': False,
                'is_active': True,
                'email_verified': True,
            },
            {
                'username': 'testuser',
                'email': 'test@medinsights.com',
                'password': 'Test123!',
                'role': 'user',
                'is_staff': False,
                'is_superuser': False,
                'is_active': True,
                'email_verified': True,
            },
        ]

        created_count = 0
        
        with transaction.atomic():
            for user_data in fake_users:
                password = user_data.pop('password')
                user = User.objects.create(**user_data)
                user.set_password(password)
                user.save()
                created_count += 1
                
                self.stdout.write(
                    self.style.SUCCESS(
                        f'✓ Created user: {user.username} ({user.email})'
                    )
                )

        self.stdout.write(
            self.style.SUCCESS(
                f'\n✅ Successfully seeded {created_count} users!'
            )
        )
        self.stdout.write(
            self.style.WARNING(
                '\n📝 Default passwords: Admin123!, Doctor123!, Nurse123!, Test123!'
            )
        )
