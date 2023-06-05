import requests
import vt
import argparse
import ipaddress
import os
import socket
import shodan
import json

# Informacion Geolocalizacion usando ipapi


def getVirusTotal(ip):
    print("-------VirusTotal-------")

    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

    params = {
        'apikey': "", 'ip': ip}

    response = requests.get(url, params=params)

    print(response.json())


def getGeo(ip):
    print("-------GeoLocalizacion-------")
    respuesta = requests.get(f'https://ipapi.co/{ip}/json/')
    if (respuesta.status_code == 200):

        salida = json.loads(respuesta.text)
        salida = {key: salida[key] for key in salida.keys(
        ) & {'city', 'region', 'country_name', 'postal', 'latitude', 'longitude'}}
        print(salida)
    else:
        print("Error al ingresar en ipapi")
        quit()
# Informacion Shodan


def getShodan(ip):
    print("-------Shodan-------")
    try:
        api = shodan.Shodan("vH5QbMTwTyHLL55C4eFfrR2HSSvnoQTQ")
        info = api.host(ip)
        return ("""
                IP: {}
                HOSTNAMES: {}
                COUNTRYNAME: {}
                PORTS: {}
                ORGANIZATION: {}
                OPERATINGSYSTEM: {}
                """.format(ip, info.get('hostnames'), info.get('country_name'), info.get('ports'), info.get('org'), info.get('os')))
    except shodan.exception.APIError as e:
        print(('Error:')+' %s\n---------------------------------\n\n' % e)
        exit(0)


# Ver Nodos Tor


def getThor(ip):

    print("-------TorNode-------")
    IpLists = requests.get("https://check.torproject.org/torbulkexitlist")
    if ip in IpLists.text:
        print("Its a Tor Node")
    else:
        print("Is Not a Tor Node")


# Metodo reverse IP


def ReverseIp(ip):
    print("-------ReverseIp-------")
    try:
        host = socket.gethostbyaddr(ip)
        print(host)
    except Exception as e:
        print(e)
        return None
# Metodo Whois


def whoisIP(ip):
    print("-------WHOIS-------")
    whois = os.system(f'whois {ip}')
    print(f'Whois: {whois}')

# Comprobamos que es una ip valida


def CheckIp(ip):
    try:
        ipaddress.IPv4Network(ip)
        return True
    except ValueError:
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Program to search about an IP')
    parser.add_argument('-i', '--ip', help='Busca Solo una IP')

    """
    whois y reverse ip siempre activos

   -t comprobar si la ip pertenece a un nodo de salida de tor
   -s comprobar en shodan
   -geo ver informacion mas detallada de la geolocalizacion 
   -vt mirar la reputacion en virustotal
    
    """

    parser.add_argument("-th", "--thor", action="store_true",
                        help="Check if Ip is a thor node")
    parser.add_argument("-s", "--shodan", action="store_true",
                        help="Check shodan Information")
    parser.add_argument("-vt", "--vt", action="store_true",
                        help="Check VirusTotal information")
    parser.add_argument("-geo", "--geo", action="store_true",
                        help="Check localitation information")

    args = parser.parse_args()
    # Vamos a crompobar que es una direccion IP valida, si no lo es, cerramos
    print(args.ip)
    if  CheckIp(args.ip):
        print("Ip  valida")

        whoisIP(args.ip)
        ReverseIp(args.ip)
        if args.thor:
            getThor(args.ip)
        if args.shodan:
            getShodan(args.ip)
        if args.vt:
            getVirusTotal(args.ip)
        if args.geo:
            getGeo(args.ip)
    else:
        print("ip no valida")
        os.exit(-1)

    

if __name__ == '__main__':
    main()
