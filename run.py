import uvicorn



IS_SECURE = True

mode = "securizat" if IS_SECURE else "vulnerabil"
uvicorn.run(f"src.{mode}.main:app", host="127.0.0.1", port=8000)
