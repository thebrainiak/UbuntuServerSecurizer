#!/bin/bash

actualizar() {

       read -p "¿Quieres actualizar y upgradear? (S or N): " c

       if [ $c == S ]

       then

# Actualizar el sistema
apt update
apt upgrade -y
       else

            echo -e "\n No se ha actualizado. \n "

       fi
}

fail2ban() {

       read -p "¿Quieres instalar fail2ban? (S or N): " c

       if [ $c == S ]

       then

# Instalar herramientas de seguridad
apt install -y fail2ban

       else

            echo -e "\n No se ha instalado Fail2ban. \n "

       fi
}

ufw() {

       read -p "¿Quieres configurar el cortafuegos UFW? (S or N): " c

       if [ $c == S ]

       then

# Configurar cortafuegos
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 65536/tcp
ufw allow https
ufw enable
       else

            echo -e "\n No se ha configurado el cortafuegos. \n "

       fi
}
# CVE-2019-11815: Vulnerabilidad de Sudo

sudovuln() {

       read -p "¿Quieres corregir la vulnerabilidad CVE-2019-11815 de sudo? (S or N): " c

       if [ $c == S ]

       then
apt install -y sudo
sed -i 's/^Defaults[[:space:]]\+env_reset$/Defaults env_reset\nDefaults:ALL !logfile/' /etc/sudoers
       else

            echo -e "\n No se ha corregido CVE-2019-11815 SUDO. \n "

       fi

}

kernelvuln() {

       read -p "¿Quieres corregir la vulnerabilidad CVE-2020-15778 del kernel de linux? (S or N): " c

       if [ $c == S ]

       then

# CVE-2020-15778: Vulnerabilidad en el kernel de Linux
apt install -y linux-image-generic-hwe-22.04
       else

            echo -e "\n No se ha corregido la vulnerabilidad del kernel. \n "

       fi
}

eximvuln() {

       read -p "¿Quieres corregir la vulnerablidad CVE-2020-10188 del demonio EXIM?? (S or N): " c

       if [ $c == S ]

       then

# CVE-2020-10188: Vulnerabilidad en el demonio Exim
apt remove -y exim4-base
       else

            echo -e "\n No se ha corregido la vulnerabilidad CVE-2020-10188 del demonio EXIM. \n "

       fi
}


sshsecure() {

       read -p "¿Quieres configurar la seguridad de SSH? (S or N): " c

       if [ $c == S ]

       then
# Deshabilitar root login y cambiar puerto SSH
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#Port 22 /Port 65536/' /etc/ssh/sshd_config

    echo "Se ha bloqueado el acceso root y el puerto ssh es el 65536"
       else

            echo -e "\n No se ha configurado la seguridad SSH. \n "

       fi
}



ipv6desactivacion() {

       read -p "¿Quieres deshabilitar IPv6 para reducir la superficie de posibles ataques? (S or N): " c

       if [ $c == S ]

       then

# Deshabilitar IPv6
sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1"/' /etc/default/grub
update-grub

# Deshabilitar IPv6 en el kernel
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
       else

            echo -e "\n No se ha deshabilitado IPv6. \n "

       fi
}


ipv6ssh() {

       read -p "¿Quieres deshabilitar IPv6 en el demonio SSH? (S or N): " c

       if [ $c == S ]

       then

# Deshabilitar IPv6 en el demonio SSH
sed -i 's/AddressFamily any/AddressFamily inet/' /etc/ssh/sshd_config
systemctl restart sshd
       else

            echo -e "\n No se ha deshabilitado IPv6 en el demonio SSH \n "

       fi
}

ipv6fail2ban() {

       read -p "¿Quieres deshabilitar IPv6 en el demonio Fail2ban? (S or N): " c

       if [ $c == S ]

       then

# Deshabilitar IPv6 en el demonio Fail2ban
sed -i 's/ignoreip =
/ignoreip =
::1/' /etc/fail2ban/jail.local
systemctl restart fail2ban
       else

            echo -e "\n No se ha deshabilitaDO IPv6 en el demonio fail2ban. \n "
       
       fi
}



ssl() {

       read -p "¿Quieres instalar certificado SSL Let's Encrypt? (S or N): " c

       if [ $c == S ]

       then

# Instalar certificado SSL Let's Encrypt
apt install -y certbot python3-certbot-nginx
certbot --nginx
       else

            echo -e "\n No se ha instalado certificado SSL Let's Encrypt \n "

       fi
}

sslipv6() {

       read -p "¿Quieres instalar certificado SSL Let's Encrypt para IPv6? (S or N): " c

       if [ $c == S ]

       then
# Instalar certificado SSL Let's Encrypt para IPv6
apt install -y certbot python3-certbot-dns-cloudflare
certbot certonly --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.ini -d example.com -d www.example.com
       else

            echo -e "\n No se ha instalado certificado SSL Let's Encrypt para IPv6 \n "

       fi
}

sslipv4() {


       read -p "¿Quieres instalar certificado SSL Let's Encrypt para IPv4 (S or N): " c

       if [ $c == S ]

       then

# Instalar certificado SSL Let's Encrypt para IPv4
certbot certonly --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.ini -d example.com -d www.example.com
       else

            echo -e "\n No se ha instalado certificado SSL Let's Encrypt para IPv4. \n "

       fi
}

selinux() {

       read -p "¿Quieres sutituir Apparmor por SELinux? (S or N): " c

       if [ $c == S ]

       then
            #Detener Apparmor para sustituirlo por SELinux
            systemctl stop apparmor
            systemctl disable apparmor

            #Instalando SELinux
            apt install policycoreutils selinux-basics selinux-utils -y

            #Activando SELinux
            selinux-activate
            #Cambiando modo de SELinux
            perl -pi -e 's/permissive/enforcing/g' /etc/selinux/config

            echo -e "\n AppArmor ha sido deshabilitado y se ha activado la protección de SELinux en modo Enforcing. \n "

       else

            echo -e "\n No se ha instalado SELinux. \n "

       fi
}


clamav() {

       read -p "¿Quieres instalar CalmAv como antimalware? (S or N): " e

       if [ $e == S ]

       then

           #Instalando ClamAV

           wget https://www.clamav.net/downloads/production/clamav-0.105.1-2.linux.x86_64.deb

           dpkg -i clam*

           rm clam*

           apt upgrade clamav

           perl -pi -e 's/DatabaseOwner clamav/#DatabaseOwner clamav/g' /usr/local/etc/freshclam.conf
           
           echo "DatabaseOwner $USER" >> /usr/local/etc/freshclam.conf
           #Activando archivo de configuración
           mv /usr/local/etc/freshclam.conf.sample /usr/local/etc/freshclam.conf
           perl -pi -e 's/Example/#Example/g' /usr/local/etc/freshclam.conf
           #Actualizando Base de Datos
           freshclam

           #Instalando interfaz grafica
           apt install clamtk

          #Activando el servicio de Clamav
           systemctl start clamav-freshclam

           #Añadimos al Cron la regla de que se realice un análisis de todo el sistema cada día

           echo -e "\n Se ha instalado y configurado ClamAV como antimalware \n "

        else

           echo -e "\n No se ha instalado ClamAV. \n "

        fi
}

instarkhunter() {

        read -p "¿Quieres instalar RKHunter para buscar rootkits? (S or N): " f

        if [ $f == S ]

        then
             #Instalando RKHunter para buscar rootkits
             apt install rkhunter

             perl -pi -e 's/UPDATE_MIRRORS=0/UPDATE_MIRRORS=1/g' /etc/rkhunter.conf
             perl -pi -e 's/MIRRORS_MODE=1/MIRRORS_MODE=0/g' /etc/rkhunter.conf
             perl -pi -e 's/WEB_CMD/#WEB_CMD/g' /etc/rkhunter.conf
             echo "WEB_CMD=""" >> /etc/rkhunter.conf

             #Lo configuramos para que se realice un análisis de forma diaria
             perl -pi -e 's/CRON_DAILY_RUN=""/CRON_DAILY_RUN="true"/g' /etc/default/rkhunter
             perl -pi -e 's/CRON_DB_UPDATE=""/CRON_DB_UPDATE="true"/g' /etc/default/rkhunter
             perl -pi -e 's/APT_AUTOGEN="false"/APT_AUTOGEN="true"/g' /etc/default/rkhunter

             #Actualizamos rkhunter

             rkhunter --update

             echo -e "\n Se ha instalado y configurado RKHUnter para buscar rootkits. \n "

         else

             echo -e "\n No se ha instalado RKHunter. \n "
         fi

}

instachkrootkit() {

       read -p "¿Quieres instalar chkrootkit? (S or N): " g

       if [ $g == S ]

       then
            #Instalando chkrootkit

            apt install chkrootkit

            #Analisis de archivos

            chkrootkit

            echo -e "\n Se ha instalado y configurado chkrootkit para buscar rootkits y malware. \n "
       else

            echo -e "\n No se ha instalado chkrootkit. \n "

       fi
}

kernelproteccion() {

       read -p "¿Deseas proteger el Kernel? (S or N): " i

       if [ $i == S ]

       then

#PROTEGIENDO EL KERNEL

echo "kernel.exec-shield=1
kernel.randomize_va_space=1
# Enable IP spoofing protection
net.ipv4.conf.all.rp_filter=1
# Disable IP source routing
net.ipv4.conf.all.accept_source_route=0
# Ignoring broadcasts request
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_messages=1
# Make sure spoofed packets get logged
net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf

             echo -e "\n Se ha protegido el kernel. \n "

        else

             echo -e "\n No se ha protegido el Kernel. \n "
        fi
}



suricata() {
        read -p "¿Deseas instalar Suricata como IDPS? (S or N): " j

        if [ $j == S ]

        then

             #Desactivando IPV6

             add-apt-repository pp:oisf/suricata-stable
             apt update
             apt install suricata jq

             echo -e "\n Se ha instalado y configurado Suricata \n "
        else

             echo -e "\n No se ha instalado y configurado Suricata \n"
        fi
}


despedida() {

              echo -e "\n \e[31m AVISO: Esto no garantiza nada pero complica las cosas a un atacante. \e[31m \n "

              echo -e "\n \e[1m \e[34m [*] ES NECESARIO REINICIAR EL PC PARA APLICAR LOS CAMBIOS \e[34m \e[1m \n "
}

    read -p "¿Estas listo para securizar tu Linux Ubuntu Server 22.04?: ( S or N )  " m
    if [ $m == S ]

    then
    actualizar
    fail2ban
    ufw
    sudovuln
    kernelvuln
    eximvuln
    sshsecure
    ipv6desactivacion
    ipv6ssh
    ipv6fail2ban
    ssl
    sslipv6
    sslipv4
    selinux
    clamav
    instarkhunter
    instachkrootkit
    kernelproteccion
    suricata
    despedida

    echo "Se ha completado la securización de tu Linux Ubuntu Server 22.04, es recomendable instalar también immunify360."
    else

         echo -e "\n \e[31m La securización ha sido cancelada. \e[31m \n "
    fi