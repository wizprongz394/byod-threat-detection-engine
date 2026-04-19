with open("largefile.txt", "wb") as f:
    f.write(b"A" * 50 * 1024 * 1024)  # 50 MB