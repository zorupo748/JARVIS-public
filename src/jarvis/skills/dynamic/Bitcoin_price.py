import requests

def get_bitcoin_price():
    url = "https://api.coindesk.com/v1/bpi/currentprice.json"
    response = requests.get(url)
    data = response.json()
    return data["bpi"]["USD"]["rate_float"]

print(get_bitcoin_price())