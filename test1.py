import requests
import os


def set_url(query):
        return f"https://unsplash.com/napi/search/photos?query={query}&xp=&per_page=1&page=1"

def make_request(query):
    url = set_url(query)
    headers = {
            "Accept":	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Encoding":	"gzip, deflate, br",
            "Accept-Language":	"en-US,en;q=0.5",
            "Host":	"unsplash.com",
            "User-Agent":	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0"
        }
    return requests.request("GET",url, headers=headers)

def get_data(self):
    data = make_request().json()
    return data

def Scrapper(query):
    data = make_request(query).json()
    for item in data['results']:
        name = item['id']
        url = item['urls']["full"]
        print (url)


if __name__ == "__main__":
    Scrapper("los angeles")



