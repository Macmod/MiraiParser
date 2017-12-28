# Mirai Encoder/Decoder
Codificador/decodificador de bytes Mirai usando trechos seletos do código-fonte original.


## Configuração
Apenas rode o `make` no diretório principal para compilar ambos os módulos:

 - `a2b` (attack to binary) - recebe uma instrução de ataque e codifica em bytes;
 - `b2a` (binary to attack) - recebe bytes da e decodifica em uma instrução de ataque.


## Decoder
O decodificador é baseado no código em C que roda nos bots, obtendo comandos binários do Comando e Controle e realizando ataques.

Exemplo:

```bash
$ echo "000e0000001400017f0000012000" | xxd -r -p | ./b2a
udp 127.0.0.1/32 20
```

O decodificador é de uso único: ele lê todos os bytes do `stdin` e, quando a entrada fecha, produz a resposta.

Para maior facilidade, em posse de um logfile com comandos Mirai, rode o utilitário `decoder`:

```bash 
$ python decoder.py logfile > logfile-decoded
```


## Encoder
O codificador é baseado no código em Go que roda no servidor de Comando e Controle, recebendo comandos em texto pleno do operador, traduzindo-os para binário e encaminhando para os bots.

Diferentemente do decodificador, o codificador pode receber vários comandos para codificar separados por quebra de linha, uma vez que recebe entrada em texto pleno.

Exemplo:

```bash
$ echo "udp 127.0.0.1/32 20" | ./a2b | xxd -ps
000e0000001400017f0000012000
```

É possível consultar a tabela de ataques enviando `?` para o `a2b`, da mesma forma que o operador faria.
