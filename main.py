from src.api import *
import os
from dotenv import load_dotenv


if __name__ == '__main__':
    load_dotenv()
    app.run(host=os.getenv('HOST_IP'), debug=True)

