from locust import HttpUser, task

class MyUser(HttpUser):

    @task
    def home(self):
        self.client.get("/")