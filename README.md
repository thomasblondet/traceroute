# traceroute

Implémentation minimale de `traceroute`.

`traceroute` est une commande qui permet de suivre le chemin que prend un paquet vers sa destination.
Le programme envoie des paquets UDP avec un TTL (*Time to Live*) de plus en plus grand.
Le TTL limite le nombre de routeurs qu'un paquet peut traverser. À chaque routeur, il est diminué de 1.
Quand il arrive à 0, le routeur abandonne le paquet et peut renvoyer une réponse ICMP Time Exceeded.

En commençant avec un TTL de 1, puis de 2, de 3, etc., on peut découvrir les routeurs sur le chemin jusqu'à la destination.
Quand la destination répond avec un message ICMP Port Unreachable, le programme considère qu'elle est atteinte.

```bash
make
# sudo est nécessaire pour créer une raw socket
sudo ./traceroute <hostname ou adresse IP>
```
