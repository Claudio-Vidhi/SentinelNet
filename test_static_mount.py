import unittest
from fastapi.testclient import TestClient
from app_server import app

class TestStaticMount(unittest.TestCase):
    def test_static_served(self):
        client = TestClient(app)
        r = client.get("/static/js/.gitkeep")
        self.assertEqual(r.status_code, 200)

if __name__ == "__main__":
    unittest.main()
