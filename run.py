import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)


# http://127.0.0.1:8000/admin?token=ojyN9hKxf79raj2he6JeVCSLsuRYiqlZRUdmOxBs6AI