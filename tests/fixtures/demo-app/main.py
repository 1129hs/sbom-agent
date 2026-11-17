from auth import create_token
from fastapi import FastAPI, UploadFile
from upload import read_image_size

app = FastAPI()


@app.post("/login")
def login(user_id: str):
    return {"token": create_token(user_id)}


@app.post("/upload")
async def upload(file: UploadFile):
    return {"size": read_image_size(await file.read())}
