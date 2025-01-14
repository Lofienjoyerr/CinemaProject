from django.db import models
from django.contrib.auth import get_user_model


def avatar_path(instance, *args) -> str:
    if instance.id:
        return f'cinema/movie_{instance.id}/avatar.jpeg'

    last = Movie.objects.last()
    if last:
        return f'cinema/movie_{last.id + 1}/avatar.jpeg'
    return f'cinema/movie_1/avatar.jpeg'


def b_avatar_path(instance, *args) -> str:
    if instance.id:
        return f'cinema/movie_{instance.id}/b_avatar.jpeg'

    last = Movie.objects.last()
    if last:
        return f'cinema/movie_{last.id + 1}/b_avatar.jpeg'
    return f'cinema/movie_1/b_avatar.jpeg'


def trailer_path(instance, *args) -> str:
    if instance.id:
        return f'cinema/movie_{instance.id}/trailer.mp4'

    last = Movie.objects.last()
    if last:
        return f'cinema/movie_{last.id + 1}/trailer.mp4'
    return f'cinema/movie_1/trailer.mp4'


class Movie(models.Model):
    title = models.CharField(max_length=254, db_index=True)
    description = models.TextField()
    genres = models.ManyToManyField('Genre', related_name="movies")
    duration = models.DurationField()
    avatar = models.ImageField(upload_to=avatar_path, default='cinemaApp/default_avatar.jpeg')
    b_avatar = models.ImageField(upload_to=b_avatar_path, default='cinemaApp/default_b_avatar.jpeg')
    trailer = models.FileField(upload_to=trailer_path, blank=True, null=True)


class Genre(models.Model):
    title = models.CharField(max_length=62)


class Cinema(models.Model):
    name = models.CharField(max_length=254)
    address = models.CharField(max_length=254)


class Hall(models.Model):
    cinema = models.ForeignKey("Cinema", on_delete=models.CASCADE, related_name="halls")
    name = models.CharField(max_length=126)


class Seat(models.Model):
    class Status(models.TextChoices):
        CHEAP = "CHEAP", "Cheap"
        REGULAR = "REGULAR", "Regular"
        VIP = "VIP", "VIP"

    hall = models.ForeignKey("Hall", on_delete=models.CASCADE, related_name="seats")
    row = models.PositiveIntegerField()
    place = models.PositiveIntegerField()
    status = models.CharField(max_length=7, choices=Status, default=Status.REGULAR)


class Session(models.Model):
    movie = models.ForeignKey("Movie", on_delete=models.CASCADE, related_name="sessions")
    hall = models.ForeignKey("Hall", on_delete=models.CASCADE, related_name="sessions")
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    cheap_price = models.PositiveIntegerField()
    regular_price = models.PositiveIntegerField()
    vip_price = models.PositiveIntegerField()


class Ticket(models.Model):
    session = models.ForeignKey("Session", on_delete=models.PROTECT, related_name="tickets")
    user = models.ForeignKey(get_user_model(), on_delete=models.PROTECT, related_name="tickets")
    seat = models.ForeignKey("Seat", on_delete=models.PROTECT, related_name="tickets")
