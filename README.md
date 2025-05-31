# PASS - Plataforma para Consultas Médicas

**PASS** é uma plataforma destinada a **clínicas médicas, hospitais** e **consultórios** para gerenciar **consultas, médicos, pacientes e prontuários eletrônicos** de forma eficiente, segura e automatizada.

## 🚀 Funcionalidades

- **Autenticação de usuários** (pacientes, médicos, recepcionistas e administradores).
- **Gestão de usuários** (pacientes, médicos, recepcionistas e administradores).
- **Agendamento de consultas** com verificação de disponibilidade de médicos.
- **Histórico de consultas e prontuários eletrônicos**.
- **Sistema de notificações** (WhatsApp, SMS e E-mail) para agendamentos e lembretes.
- **Sistema de pagamento online** (via Stripe ou Pix).
- **Dashboard administrativo** para monitoramento e relatórios.

## 🛠️ Tecnologias Utilizadas

### **Backend**
- **Java 17** + **Spring Boot**
- **Spring Security** + **JWT** + **OAuth2** (Autenticação)
- **Spring Data JPA** + **PostgreSQL** (Persistência)
- **Redis** (Cache)
- **RabbitMQ/Kafka** (Mensageria)
- **JUnit** + **Mockito** (Testes)
  
### **Frontend**
- **Angular 17** (Web UI)
- **Angular Material** (Componentes)
- **RxJS** + **NGXS** (Gerenciamento de estado)
- **JWT** + **Guards** (Autenticação)
- **Cypress** (Testes automatizados)
- **Chart.js** (Gráficos e dashboards)

### **Desktop**
- **Java Swing** + **FlatLaf** (Interface Desktop)
- **Autenticação com JWT**
- **HTTP Requests** para backend
- **Persistência local para uso offline**

### **DevOps & Infraestrutura**
- **Docker** + **Kubernetes** (Deploy escalável)
- **GitLab CI/CD** (Pipeline de automação)
- **SonarQube** (Qualidade de código)
- **Terraform** + **Ansible** (Infraestrutura como código)
- **Prometheus** + **Grafana** (Monitoramento)

## 🔄 Como Rodar o Projeto

### **Passo 1: Clone o repositório**

```bash
git clone https://github.com/seu-usuario/pass-backend.git
cd pass-backend
```

### **Passo 2: Construir e rodar o backend com Docker**

Certifique-se de ter o Docker e o Docker Compose instalados.

No diretório do projeto, execute o comando:

```bash
docker-compose up --build
```
Isso irá:

- Criar os containers necessários.
- Iniciar a aplicação backend na porta 8080.
- Configurar o PostgreSQL e Redis via Docker.

### Passo 3: Acesse a aplicação

Após a construção do Docker, a aplicação backend estará rodando localmente em:  

[http://localhost:8080](http://localhost:8080)

Para testar a API, você pode acessar a URL `/api/hello` para verificar se o backend está rodando corretamente.

### Passo 4: Acesse o Frontend (se aplicável)

Caso haja uma interface frontend em Angular, basta rodar o servidor de desenvolvimento:

```bash
ng serve --open
```
Isso abrirá o frontend em:
http://localhost:4200

## ⚙️ Como Contribuir

1. Fork o repositório.
2. Crie uma branch para a sua feature (`git checkout -b feature/nome-da-feature`).
3. Faça as modificações e commite (`git commit -am 'Adiciona nova feature'`).
4. Push para a sua branch (`git push origin feature/nome-da-feature`).
5. Abra um pull request explicando as alterações realizadas.

## 📄 Licença

Todos os direitos reservados. Este projeto **não pode ser utilizado, modificado ou distribuído** sem a permissão expressa do autor.

## 📞 Contato

Se tiver alguma dúvida ou sugestão, sinta-se à vontade para entrar em contato:

- **Email:** arthuraugustinho35@gmail.com
- **GitHub:** [https://github.com/ArhturAugustinho](https://github.com/ArhturAugustinho)
