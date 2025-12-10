votar(votoencriptado, zkp)
if zkp in zkps then rechazar voto
else verificar(zkp, merkle)


//Homomorific encryption
acumuladoencriptado = acumuladoencriptado * votoencriptado


//Desencriptado
desencriptado(acumulado, concat(PK_1, PK_2)) = acumulado + voto desencriptado

genera ZKP de que el resultado publicado es válido