# Instale a Elven Observability

1. Na [release v1.0.1](https://github.com/elven-observability/stack-observability-k8s/releases/tag/v1.0.1), baixe **elven-instalacao-v1.0.1.zip** e seu **.zip.sha256**, confira o checksum e extraia em uma pasta nova. O ZIP contém o instalador e o pacote completo; não precisa clonar o repositório.
2. Com sua equipe de plataforma, preencha **plataforma/cliente.toml** usando o modelo que acompanha o kit. Isso é feito uma vez: cluster, tenant, namespaces e coleta aprovada. **O token não vai nesse arquivo.** Veja [Preparar a configuração](plataforma/PREPARAR.md).
3. Na pasta extraída, abra um terminal preparado com acesso ao cluster e execute:

   ```sh
   ./instalar
   ```

O instalador confere o ambiente, gera o plano para revisão e pede confirmação antes de instalar. Se pedir o token, cole-o pelo terminal: os caracteres não aparecem. A credencial fica no Kubernetes e é reutilizada nas próximas execuções compatíveis, enquanto válida.

A instalação não reinicia suas aplicações. Depois, a equipe de aplicações ativa um serviço piloto e confirma os sinais com a Elven antes de ampliar.

**Precisa de ajuda?** Compartilhe só a mensagem de erro, sem token, kubeconfig ou dump de Secrets. Não execute duas instalações em paralelo. Se der erro após iniciar a instalação, confira o estado com a plataforma antes de repetir.
