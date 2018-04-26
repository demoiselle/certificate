#!/bin/bash

clear

## SETAR O JAVA HOME em .bashrc
echo $JAVA_HOME


#Colocar o Pin do Token aqui
PASSWORD="senha"

#NAO ALTERAR!
DSANAME="SERPRO"

#Apontar para o caminho onde estão os jars  que devem ser assinados
JARPATH="/home/80621732915/git/certificate/example/assinadorweb-example/src/main/webapp"

#lista os dados do token, inclusive o apelido
keytool -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg drivers.config -storepass $PASSWORD -list


for jarfile in $(ls $JARPATH/ass*.jar); do
    jarfile_signed="${jarfile%.jar}-assinado.jar"
    echo "Gerando jar assinado para $jarfile em $jarfile_signed"
    #Nome do arquivo a ser assinado
    #JARFILE="security-applet-customizada-1.0.0.jar"

    #nome ddo arquivo depois de assinado
    #JARFILESIGNED="security-applet-customizada-1.0.0-assinado.jar"

    #apelido do certificado, rodar o script uma primeira vez no console e copiar o apelido cara este script
    ALIAS="SERVICO FEDERAL DE PROCESSAMENTO DE DADOS SERPRO:CETEC's Autoridade Certificadora do SERPRO Final v3 ID"
	    
    #assina o jar
#    jarsigner -sigalg SHA512withRSA -verbose -J-Djava.security.debug=sunpkcs11 -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg drivers.config -storepass $PASSWORD -sigfile $DSANAME -signedjar $jarfile_signed -verbose $jarfile "$ALIAS"

   jarsigner -tsa http://sha256timestamp.ws.symantec.com/sha256/timestamp -sigalg SHA512withRSA -verbose -J-Djava.security.debug=sunpkcs11 -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg drivers.config -storepass $PASSWORD -sigfile $DSANAME -signedjar $jarfile_signed -verbose $jarfile "$ALIAS"
# -tsa https://timestamp.geotrust.com/tsa

done

exit 0
