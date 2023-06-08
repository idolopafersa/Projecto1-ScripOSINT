import requests
import vt
import argparse
import ipaddress
import os
import socket
import shodan
import json

keys = json.load(open('ApiKeys.json'))

# Informacion Geolocalizacion usando ipapi


def getVirusTotal(ip):
    EscribirFichero("-------VirusTotal-------")

    url = f'https://www.virustotal.com/vtapi/v2/{ip}/report'

    params = {
        'apikey': keys['ApiVirusTotal'], 'ip': ip}

    response = requests.get(url, params=params)
    
    
    
    EscribirFichero(response)
    

def getGeo(ip):
    EscribirFichero("-------GeoLocalizacion-------")
    respuesta = requests.get(f'https://ipapi.co/{ip}/json/')
    if (respuesta.status_code == 200):

        salida = json.loads(respuesta.text)
        salida = {key: salida[key] for key in salida.keys(
        ) & {'city', 'region', 'country_name', 'postal', 'latitude', 'longitude'}}
        EscribirFichero(salida)
    else:
        EscribirFichero("Error al ingresar en ipapi")
# Informacion Shodan


def getShodan(ip):
    EscribirFichero("-------Shodan-------")
    
    try:
        api = shodan.Shodan(keys['ApiShodan'])
        info = api.host(ip)
        return ("""
                IP: {}
                
                """.format(ip))
    except shodan.exception.APIError as e:
        EscribirFichero(('Error:')+' %s\n---------------------------------\n\n' % e)
        exit(0)


# Ver Nodos Tor


def getThor(ip):

    EscribirFichero("-------TorNode-------")
    IpLists = requests.get("https://check.torproject.org/torbulkexitlist")
    if ip in IpLists.text:
        EscribirFichero("Its a Tor Node")
    else:
        EscribirFichero("Is Not a Tor Node")


# Metodo reverse IP


def ReverseIp(ip):
    EscribirFichero("-------ReverseIp-------")
    try:
        host = socket.gethostbyaddr(ip)
        EscribirFichero(host)
    except Exception as e:
        EscribirFichero(e)
        return None
# Metodo Whois


def whoisIP(ip):
    EscribirFichero('-------WHOIS-------')
    whois = os.system(f'whois {ip}')
    EscribirFichero(f'Whois: {whois}')

# Comprobamos que es una ip valida


def CheckIp(ip):
    try:
        ipaddress.IPv4Network(ip)
        return True
    except ValueError:
        return False


def EscribirFichero(texto):
    with open("output.txt", 'a') as f:
        f.write(f'{texto}\n')


def procesarip(ip,thor,shodan,vt,geo):
    EscribirFichero(f'-----{ip}-----')
    if CheckIp(ip):
       
        EscribirFichero('Ip  valida')

        whoisIP(ip)
        ReverseIp(ip)
        if thor:
            getThor(ip)
        if shodan:
            getShodan(ip)
        if vt:
            getVirusTotal(ip)
        if geo:
            getGeo(ip)
    else:
        EscribirFichero("ip no valida")
        


def main():
    
    
    parser = argparse.ArgumentParser(
        description='Program to search about an IP')
    parser.add_argument('-i', '--ip', help='Busca Solo una IP')
    parser.add_argument('-l', '--list', help='Busca Una lista de IP')
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
   

    if args.ip:
        ip = args.ip
        procesarip(ip,args.thor,args.shodan,args.vt,args.geo)

    elif args.list:
        filename = args.list
        with open(filename, 'r') as f:
            for ip in f:
                ip = ip.strip()
                procesarip(ip,args.thor,args.shodan,args.vt,args.geo)
    else:
        print("Error al ingresar parametro")




    



    

if __name__ == '__main__':
    main()
