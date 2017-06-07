**Caso esteja iniciando um projeto novo utilize o componente Demoiselle Signer (https://github.com/demoiselle/signer)**

# Demoiselle Certificate
================================

O Demoiselle Certificate é um componente para facilitar a implementação de assinatura digital usando certificado.
O componente implementa o padrão de assinatura básica ADRB em CADES do ICPBrasil, conforme o DOC-ICP-15.

O componente é dividido de acordo com suas funcionalidades:

* **demoiselle-certificate-core:** fornece acesso ao token, carregamento de certificado e API para dados de um certificado ICPBrasil

* **demoiselle-certificate-ca-icpbrasil:** possui as cadeias de autoridades certificadores ICPBrasil válidas

* **demoiselle-certificate-criprography:** provê funcionalidades de criptografia

* **demoiselle-certificate-signer:** realiza assinatura digital e verificação de assinatura

* **demoiselle-certificate-desktop:** possui funcionalidades para desenvolvimento aplicação desktop via Java Web Start

Funcionalidades ainda não implementadas no componente:

* Assinatura com carimbo de tempo
* Assinatura no padrão XADES (assinatura em XML)
* Assinatura no padrão PADES (assinatura em PDF)

## Repositório Maven

	<repositories>
		<repository>
			<id>demoiselle.sourceforge.net-release</id>
			<url>http://demoiselle.sourceforge.net/repository/release</url>
		</repository>
		<repository>
			<id>demoiselle.sourceforge.net-snapshot</id>
			<url>http://demoiselle.sourceforge.net/repository/snapshot</url>
		</repository>
	</repositories>


## Documentação

A documentação completa está disponível em: [Documentação](http://demoiselle.sourceforge.net/docs/components/certificate/reference/1.1.0/)

## Modelo e Aplicação de Exemplo

Disponibilizamos uma aplicação de exemplo seguindo o modelo descrito abaixo em: [Github](https://github.com/demoiselle/certificate/tree/master/example)

#### Aplicação Web

![Alt text](assinador_1.png?raw=true)

1. O usuário escolhe os arquivos que deseja assinar.
2. O usuário clica no botão *assinar*, que dispara uma requisição para baixar o JNLP.
3. A requisição deve conter as identificações dos arquivos selecionados, os quais devem trafegar dentro do corpo da requisição numa conexão segura. Jamais deve-se trafegar as identificações na URL. Recomenda-se fazer uma requisição POST via HTTPS. Recomenda-se usar o formato JSON, passando as identificações como *arrays*. Definir o cabeçalho *Content-Type: application/json*.
4. O serviço (ou página dinâmica) deve recuperar as identificações dos arquivos no corpo da requisição, criar uma chave única e seguro (**Token**) e associar as identificações à chave de forma persistente.
5. O serviço (ou página dinâmica) deve criar um novo arquivo JNLP contendo no seu corpo o **Token** criado e uma **URL** fixa que auxiliará o assinador a recuperar os arquivos e a submeter as assinaturas posteriormente. Por questões de segurança esta URL não deve conter tokens, nem chaves, nem identificadores de sessão.
6. O serviço (ou página dinâmica) devolve a resposta com o status *HTTP 200* contendo o arquivo JNLP no corpo e no cabeçalho o *Content-Type: application/x-java-jnlp-file*.

![Alt text](assinador_2.png?raw=true)

Enquanto o proceso de assinatura ocorre em paralelo, recomenda-se que a aplicação Web fique em estado de espera. De tempos em tempos, ou via notificação do servidor, a tela deve verificar o status do processo de assinatura para desbloquear a tela apresentando uma mensagem de sucesso ou de falha para o usuário.

#### Aplicação Java SE

![Alt text](assinador_3.png?raw=true)

1. Após o download da aplicação Java SE, o usuário deve executá-la (ou ela deve executar automaticamente). Durante o processo de inicialização, a aplicação deve acessar a URL auxiliar definida nos atributos do JNLP para obter os arquivos.
2. A aplicação deve disparar uma requisição GET via HTTPS para a **URL** informando o **Token**, ambos obtidos nos atributos do JNLP. O **Token** deve ser passado no cabeçalho *Authorization: TOKEN __Token__*. Por questões de segurança, NUNCA trafegue o **Token** na **URL**. Definir o cabeçalho *Accept: application/zip*.
3. Ao receber a requisiçao, o serviço (ou página dinâmica) que responde pela **URL** deve resgatar da base os arquivos associados ao **Token**.
4. O serviço (ou página dinâmica) devolve a resposta com o status *HTTP 200* contendo os arquivos zipados no corpo. No cabeçalho deve conter *Content-Type: application/zip*. Os arquivos a serem assinados devem estar agrupados na raiz do ZIP. Fica a critério do projeto definir se os arquivos que compõem o ZIP serão os arquivos originais ou apenas os seus *hashs*.
5. Ao final da requisição, a aplicação descompacta o arquivo ZIP para obter os arquivos a serem assinados. Recomenda-se exibir para o usuário o nome dos arquivos que serão assinados.
6. O processo de assinatura tem início de forma automática, disparando todos os passos da interação com o usuário para obter o certificado digital e proceder com a assinatura propriamente dita.
7. Após a conclusão do processo de assinatura, a aplicação deve fazer uma requisição POST via HTTPS para a **URL** informando o **Token** no cabeçalho *Authorization: TOKEN __Token__* e as assinaturas zipadas no corpo. Os arquivos a serem assinados devem estar agrupados na raiz do ZIP. No cabeçalho da requisição deve conter também *Content-Type: application/zip*.
8. Ao receber a requisiçao, o serviço (ou página dinâmica) deve resgatar da base os arquivos associados ao **Token**, verificar se a assinatura corresponde ao arquivo no servidor, guarda a assinatura na base de dados associando-as aos arquivos originais, desassocia o **Token** dos arquivos e descarta o **Token**.
9. O serviço (ou página dinâmica) devolve a resposta com o status *HTTP 204* e a aplicação cliente se encerra.
 

