from database.database import get_statistics_db, update_statistics_db
print(get_statistics_db())
update_statistics_db(100, 80, 10, 10, 5)
print(get_statistics_db())
