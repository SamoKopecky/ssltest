
Dobrý ďen,

pokúšal som sa vyriešiť chybu ktorá nastala pri skenovaní serveru www.linux.cz. Myslím
si že jedna z príčin vďaka ktorej nefungoval scan bola "zlá" konfigurácia `openssl` 
knižnice pomcou konfiguračného súboru.

Pretože keď som skúsil skenovať na dvoch rôznych strojoch na jednom scan fungoval a
vypísal že server podporuje iba verziu `TLSv1` a ostatné `TLS` verzie nepodporuje. Na 
druhom nefungoval presne ako Vám keď sťe testovali program.

Časť výstupu programu pri fungovaní:

```
Protocol support:
	Supported protocols:
		TLSv1->2
	Unsupported protocols:
		TLSv1.1->1
		TLSv1.2->4
		TLSv1.3->2
	rating: 4
```

Neskoršie som zistil že ak zmením konfiguračný súbor `/etc/ssl/openssl.cnf` a to 
presnejšie takto:

- pridal som na koniec súboru tento blok textu, prípadne zmenil hodnotu `MinProtocol`
na `TLSv1` a `CipherString` na `DEFAULT@SECLEVEL=0` ak už text existoval v súbore.
```
[default_conf]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1
CipherString = DEFAULT@SECLEVEL=0
```

- ďalej som pridal na začatok súboru:

`openssl_conf = default_conf`

Keď som reštartoval PC a skúsil scan znova na www.linux.cz scan prebehol úspešne aj 
na stroji na ktorom to pred zmenou súboru nefungovalo.

Keďže program používa na vytvorenie prvotného spojenia vstavanú python knižnicu `ssl`
ktorá používa inštanciu nainštalovanej knižnice `openssl` v OS, myslím si že
program práve preto nebol schopný skenovať tento server, pretože mu to knižnica 
`openssl` nedovolila.

Chcel by som Vás teda poprosiť ak by ste mohli vyskúšať spraviť túto zmenu v 
konfiguračnom súbore ak stále bude teda program končiť chybou.

V zložke sú pridané súbory `docker-compose.yaml` a `Dockerfile` ktoré vytvoria
kontajner na ktorom je možné testovať program ak by sťe nechceli meniť 
konfiguračný súbor na hostovaciom OS. Samozrejme je potreba mať nainštalovaný
docker. Build kontaineru je možné pomocou `docker-compose -up -d` a potom
sa do neho dá vstúpiť príkazom `docker exec -it bp_bp_flask_server_1 /bin/bash` a
ďalej už spusťiť program normálne. Program sa nachádza v adresári `/usr/src/app`.