import requests


def obtener_precio_ethereum():
    url = "https://api.coinbase.com/v2/prices/ETH-USD/spot"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        datos = response.json()
        precio = float(datos["data"]["amount"])
        print(f"El precio actual de Ethereum (ETH) es: ${precio:,.2f} USD")
        return precio
    except requests.RequestException as e:
        print(f"Error al consultar la API: {e}")
        return None


if __name__ == "__main__":
    obtener_precio_ethereum()