import os


def handler(request):
    name = request.args.get("name")
    cmd = "ping " + name
    os.system(cmd)


def safe_handler(request):
    name = request.args.get("name")
    print("hello " + name)


def direct_sink(request):
    os.system(input())
