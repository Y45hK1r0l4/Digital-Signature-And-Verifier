# Generated by Django 5.0.8 on 2025-03-26 11:36

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='SignedFile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file', models.FileField(upload_to='signed_files/')),
                ('signature', models.TextField()),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
