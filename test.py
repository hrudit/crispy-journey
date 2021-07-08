import requests
import os
class Unsplash:
    def __init__(self,search_term, quality="full"):
        self.search_term = search_term
        self.quality = quality
        self.headers = {
            "Accept":	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Encoding":	"gzip, deflate, br",
            "Accept-Language":	"en-US,en;q=0.5",
            "Host":	"unsplash.com",
            "User-Agent":	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0"
        }

    def set_url(self):
        return f"https://unsplash.com/napi/search/photos?query={self.search_term}&xp=&per_page=1&page=1"

    def make_request(self):
        url = self.set_url()
        return requests.request("GET",url, headers=self.headers)

    def get_data(self):
        self.data = self.make_request().json()

    def save_path(self,name):
        download_dir = "unsplash"
        if not os.path.exists(download_dir):
            os.mkdir(download_dir)
        return f"{os.path.join(os.path.realpath(os.getcwd()),download_dir,name)}.jpg"


    def Scrapper(self):
        for page in range(0, 2):
            self.make_request()
            self.get_data()
            for item in self.data['results']:
                name = item['id']
                url = item['urls'][self.quality]
                print(url)

if __name__ == "__main__":
    scrapper = Unsplash("new york city")
    scrapper.Scrapper()