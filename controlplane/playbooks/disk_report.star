df = sys.exec.run("df", "-h")
print(df["output"])
du = sys.exec.run("du", "-xhd", "1", "/")
print(du["output"])
