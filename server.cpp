#include "function.h"
#include "factory.h"
#include "MyDb.h"
#include "MyLog.h"
#include "timer.h"

Timer myTimer;                         //时间轮定时器
#define TimeSLOT 60

vector<int> clients;                   //存储客户端的描述符
unordered_map<string, int> name_to_fd; //<用户名称，描述符>
int epfd = epoll_create(1);            //设置epoll
static int pipefd[2];

//清除socket的定时器，已登录数组中的socket
void EraseSocket(int socket, bool IsClose = true) {
    struct epoll_event ev;
    ev.data.fd = socket;
    ev.events = EPOLLIN;
    int ret = epoll_ctl(epfd, EPOLL_CTL_DEL, socket, &ev);
    if (ret == -1)
    {
        perror("epoll_ctl");
        pthread_exit(NULL);
    }
    clients.erase(socket);
    timeMap->erase(e.first);
    if (IsClose) close(socket);
}

void sig_handler(int sig) {
    int save_errno = errno;
    int msg = sig;
    sendCycle(pipefd[1], (char*)&msg, 1, 0);
    errno = save_errno;
}

void timer_handler() {
    myTimer.tick();
    alarm(TimeSLOT);
}

void cb_func(int* Fd) {
    int ret=epoll_ctl(epfd, EPOLL_CTL_DEL, *Fd, 0);
    ERROR_CHECK(ret, -1, "Timer cb_Func");
    EraseSocket(*Fd);
    cout << "close fd: " << *Fd << endl;
}

int setnonblocking(int fd) {
    int old_option = fcncl(fd, F_GETFL);
    int new_option=old_option|O_NONBLOCK;
    fcntl(fd, F_SETFL, new_option);
    return old_option;
}

int addsig(int epollfd, int fd) {
    struct sigaction sa;
    memset(&sa, '\0', sizeof(sa));
    sa.sa_handler = sig_handler;
    sa.sa_flags |= SA_RESTART;
    sigfillset(&sa.sa_mask);
    assert(sigaction(sig, &sa, NULL) != -1);
}

void addfd(int epollfd, int fd) {
    epoll_event event;
    event.data.fd = fd;
    event.enents=EPOLLIN|EPOLLET;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
    setnonblocking(fd);
}

int main()
{
    /******************启动多线程，并绑定TCP的socket**********************/
    Factory f;
    Packet packet;
    f.startFactory(); //启动工厂
    int sockfd;
    tcpInit(&sockfd); //创建TCP连接
    bool flag;

    /******************设置epoll，监听sockfd与客户端描述符**********************/
    ERROR_CHECK(epfd, -1, "epoll_create");
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLRDHUP;
    ev.data.fd = sockfd;
    int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev); //监听sockfd
    ERROR_CHECK(ret, -1, "epoll_ctl");

    /******************定时器相关**********************/
    ret = socketpair(PF_UNIX, SOCK_STREAM, 0, pipefd);
    ERROR_CHECK(ret, -1, "socketpair");
    setnonblocking(pipefd[1]);
    addfd(epfd, pipefd[0]);
    addsig(SIGALRM);
    bool timeout = false;
    alarm(TimeSLOT);

    /************************启动服务器,并连接服务器数据库************************************/
    chdir("../workspace/");
    MyDb db;
    db.initDB("localhost", "test1", "test1", "Netdisk");
    string sql;
    int dataLen = 0;
    char buf[1000] = {0};

    bool stop_server = false;
    while (!stop_server)
    {
        struct epoll_event evs[MAXEVENTS]; //需要监听sockfd, 以及所有accept的newfd
        int nfds = epoll_wait(epfd, evs, MAXEVENTS, 10000);
        ERROR_CHECK(nfds, -1, "epoll_wait");
        for (int i = 0; i < nfds; i++)
        {
            /************************有新的客户端连接**************************/
            /**
             * 接收新连接的描述符信息：
             * logIn 登陆
             * signIn 注册
             * puts 上传操作
             * gets 下载操作
             * quit 退出
            */
            if (evs[i].data.fd == sockfd)
            {
                int newClient = accept(sockfd, NULL, NULL);
                ERROR_CHECK(newClient, -1, "accept");
                //服务器接收到客户端发来的命令
            accept_client:
                bzero(buf, sizeof(buf));
                recvCycle(newClient, &dataLen, 4);
                recvCycle(newClient, buf, dataLen);
                string orders(buf);
                cout << "receive orders From newClient: " << orders << endl;
                stringstream ss(orders);
                string order, name, order2; //order代表命令，name代表跟在name后面的文件名，order2代表补充命令（可为空）
                ss >> order >> name >> order2;
                /************************登陆操作**************************/
                if (order == "logIn")
                {
                    string salt;
                    sql = "SELECT Salt FROM Shadow WHERE User = '" + name + "'";
                    cout << sql << endl;
                    db.select_one_SQL(sql, salt);
                    //搜寻有无此用户
                    if (salt.empty())
                    {
                        flag = false;
                        sendCycle(newClient, &flag, 1);
                        goto accept_client;
                    }
                    else
                    {
                        flag = true;
                        sendCycle(newClient, &flag, 1);
                    }
                    //若有此用户，那么将用户的盐值发送给客户端
                    packet.dataLen = strlen(salt.c_str());
                    memcpy(packet.buf, salt.c_str(), packet.dataLen);
                    sendCycle(newClient, &packet, 4 + packet.dataLen);
                    //接收用户加密后的密文cipher
                    bzero(buf, sizeof(buf));
                    recvCycle(newClient, &dataLen, 4);
                    recvCycle(newClient, buf, dataLen);
                    //进行最终的对比，判断密码是否正确
                    string s(buf);
                    string cipher;
                    sql = "SELECT Cipher FROM Shadow WHERE User = '" + name + "'";
                    cout << sql << endl;
                    db.select_one_SQL(sql, cipher);
                    if (s == cipher)
                    {
                        //密码验证成功，将描述符加入监听
                        flag = true;
                        ev.data.fd = newClient;
                        ret = epoll_ctl(epfd, EPOLL_CTL_ADD, newClient, &ev); //监听新连接上的客户端
                        ERROR_CHECK(ret, -1, "epoll_ctl");
                        clients.push_back(newClient);
                        sendCycle(newClient, &flag, 1);
                        cout << newClient << " has connected!" << endl;
                        name_to_fd[name] = newClient;
                        cout << name << ":" << newClient << endl;
                        myTimer.add(newClient);
                    }
                    else
                    {
                        //密码验证失败
                        flag = false;
                        sendCycle(newClient, &flag, 1);
                        goto accept_client;
                    }
                    LOG(name, orders);
                }
                /************************注册操作**************************/
                else if (order == "signIn")
                {
                    //在数据库中寻找是否有相同的用户
                    string s;
                    sql = "SELECT User FROM Shadow WHERE User = '" + name + "'";
                    cout << sql << endl;
                    db.select_one_SQL(sql, s);
                    if (s.empty())
                    {
                        flag = true;
                        string salt(GenerateStr(8));
                        string cipher(crypt(order2.c_str(), salt.c_str()));
                        sql = "INSERT INTO Shadow Values('" + name + "','" + order2 + "','" + salt + "','" + cipher + "')";
                        cout << sql << endl;
                        db.exeSQL(sql);
                    }
                    else
                    {
                        flag = false;
                    }
                    sendCycle(newClient, &flag, 1);
                    LOG(name, orders);
                    goto accept_client;
                }
                /************************令牌操作,用于频繁请求数据的puts和gets**************************/
                else if (order == "puts")
                {
                    //接收用户姓名
                    bzero(buf, sizeof(buf));
                    recvCycle(newClient, &dataLen, 4);
                    recvCycle(newClient, buf, dataLen);
                    string username(buf);
                    //接收目录号
                    int Dir;
                    bzero(buf, sizeof(buf));
                    recvCycle(newClient, &Dir, 4);
                    myTimer.update(name_to_fd[username]);

                    //向任务队列插入puts任务
                    cout << "upLoad thread is running..." << endl;
                    pthread_mutex_lock(&f.que.mutex);
                    Task task(newClient, orders, username, Dir);
                    f.que.insertTask(task);
                    pthread_mutex_unlock(&f.que.mutex);
                    pthread_cond_signal(&f.cond);
                }
                else if (order == "gets")
                {
                    //接收用户姓名
                    bzero(buf, sizeof(buf));
                    recvCycle(newClient, &dataLen, 4);
                    recvCycle(newClient, buf, dataLen);
                    string username(buf);
                    //接收目录号
                    int Dir;
                    bzero(buf, sizeof(buf));
                    recvCycle(newClient, &Dir, 4);
                    myTimer.update(name_to_fd[username]);

                    //向任务队列插入puts任务
                    cout << "downLoad thread is running..." << endl;
                    pthread_mutex_lock(&f.que.mutex);
                    Task task(newClient, orders, username, Dir);
                    f.que.insertTask(task);
                    pthread_mutex_unlock(&f.que.mutex);
                    pthread_cond_signal(&f.cond);
                }
                /************************退出操作**************************/
                else if (order == "quit")
                {
                    cout << "client quit" << endl;
                }
            }
            else if ((sockfd == pipefd[0]) && (evs[i].events & EPOLLIN))
            {
            int sig;
            char signals[1024];
            ret = recvCycle(pipefd[0], signals, sizeof(signals), 0);
            if (ret == -1 || ret==0) continue;
            else {
                for (int i = 0; i < ret; ++i) {
                    if (signals[i] == SIGALRM) {
                        timeout = true;
                        break;
                    }
                    else {
                        stop_server = true;
                    }
                }
            }
            }
            else if (evs[i].events & EPOLLRDHUP)
            {
                EraseSocket(evs[i].data.fd);
            }
        }

        /************************接收客户端发送的命令**************************/
        for (size_t i = 0; i < clients.size(); i++)
        {
            if (evs[i].data.fd == clients[i]) //客户端发来请求，主线程进行处理
            {
                //服务器接收到客户端发来的命令
                bzero(buf, sizeof(buf));
                recvCycle(clients[i], &dataLen, 4);
                ret = recvCycle(clients[i], buf, dataLen);
                if (ret == 0)
                {
                    //接收到0，说明客户端已经断开
                    ev.data.fd = clients[i];
                    ret = epoll_ctl(epfd, EPOLL_CTL_DEL, clients[i], &ev);
                    ERROR_CHECK(ret, -1, "epoll_ctl");
                    clients.erase(remove(clients.begin(), clients.end(), clients[i]), clients.end());
                }
                cout << "Main thread process orders:" << buf << endl;
                string orders(buf);
                stringstream ss(orders);
                string order, name, order2; //order代表命令，name代表跟在name后面的文件名，order2代表补充命令（可为空）
                ss >> order >> name >> order2;

                /************************ls**************************/
                if (order == "ls")
                {
                    //接收用户名
                    bzero(buf, sizeof(buf));
                    recvCycle(clients[i], &dataLen, 4);
                    recvCycle(clients[i], buf, dataLen);
                    string username(buf);
                    LOG(username, orders);
                    //接收目录号
                    int Dir;
                    recvCycle(clients[i], &Dir, 4);
                    //读取虚拟文件目录并返回
                    sql = "SELECT FileName, FileType FROM Virtual_Dir WHERE User = '" + username + "' AND Dir = " + to_string(Dir);
                    string res;
                    db.select_many_SQL(sql, res);
                    //发送信息
                    packet.dataLen = strlen(res.c_str());
                    memcpy(packet.buf, res.c_str(), packet.dataLen);
                    sendCycle(clients[i], &packet, 4 + packet.dataLen);
                }
                /************************mkdir**************************/
                else if (order == "mkdir")
                {
                    //接收用户名
                    bzero(buf, sizeof(buf));
                    recvCycle(clients[i], &dataLen, 4);
                    recvCycle(clients[i], buf, dataLen);
                    string username(buf);
                    LOG(username, orders);
                    //接收目录号
                    int Dir;
                    recvCycle(clients[i], &Dir, 4);
                    sql = "SELECT FileName FROM Virtual_Dir WHERE User = '" + username + "' AND Dir = " + to_string(Dir) + " AND FileType = 'd' AND FileName = '" + name + "'";
                    string res;
                    db.select_one_SQL(sql, res);
                    if (res.empty())
                    {
                        flag = true;
                        //创建目录
                        sql = "INSERT INTO Virtual_Dir(Dir, FileName, FileType, User) VALUES(" + to_string(Dir) + ",'" + name + "', 'd' ,'" + username + "')";
                        db.exeSQL(sql);
                    }
                    else
                    {
                        flag = false;
                    }
                    sendCycle(clients[i], &flag, 1);
                }
                /************************rmdir**************************/
                else if (order == "rmdir")
                {
                    //接收用户名
                    bzero(buf, sizeof(buf));
                    recvCycle(clients[i], &dataLen, 4);
                    recvCycle(clients[i], buf, dataLen);
                    string username(buf);
                    LOG(username, orders);
                    //接收目录号
                    int Dir;
                    recvCycle(clients[i], &Dir, 4);
                    sql = "SELECT FileName FROM Virtual_Dir WHERE User = '" + username + "' AND Dir = " + to_string(Dir) + " AND FileName = '" + name + "'";
                    string res;
                    db.select_one_SQL(sql, res);
                    if (res.empty())
                    {
                        flag = false;
                    }
                    else
                    {
                        flag = true;
                        sql = "DELETE FROM Virtual_Dir WHERE User = '" + username + "' AND Dir = " + to_string(Dir) + " AND FileName = '" + name + "'";
                        db.exeSQL(sql);
                    }
                    sendCycle(clients[i], &flag, 1);
                }
                /************************cd**************************/
                else if ("cd" == order)
                {
                    //接收用户名
                    bzero(buf, sizeof(buf));
                    recvCycle(clients[i], &dataLen, 4);
                    recvCycle(clients[i], buf, dataLen);
                    string username(buf);
                    LOG(username, orders);
                    //接收目录号
                    int Dir;
                    recvCycle(clients[i], &Dir, 4);
                    if (".." == name)
                    {
                        sql = "SELECT Dir FROM Virtual_Dir WHERE User = '" + username + "' AND FileId = " + to_string(Dir);
                    }
                    else
                    {
                        sql = "SELECT FileId FROM Virtual_Dir WHERE User = '" + username + "' AND Dir = " + to_string(Dir) + " AND FileName = '" + name + "'";
                    }
                    string res;
                    db.select_one_SQL(sql, res);
                    if (res.empty())
                    {
                        flag = false;
                        sendCycle(clients[i], &flag, 1);
                    }
                    else
                    {
                        flag = true;
                        sendCycle(clients[i], &flag, 1);
                        Dir = stoi(res);
                        sendCycle(clients[i], &Dir, 4);
                    }
                }
                /************************rm**************************/
                else if ("rm" == order)
                {
                    //接收用户名
                    bzero(buf, sizeof(buf));
                    recvCycle(clients[i], &dataLen, 4);
                    recvCycle(clients[i], buf, dataLen);
                    string username(buf);
                    LOG(username, orders);
                    //接收目录号
                    int Dir;
                    recvCycle(clients[i], &Dir, 4);
                    sql = "SELECT FileName FROM Virtual_Dir WHERE User = '" + username + "' AND Dir = " + to_string(Dir) + " AND FileType = 'f' AND FileName = '" + name + "'";
                    string res;
                    db.select_one_SQL(sql, res);
                    if (!res.empty())
                    {
                        flag = true;
                        //删除成功
                        sql = "DELETE FROM Virtual_Dir WHERE User = '" + username + "' AND Dir = " + to_string(Dir) + " AND FileType = 'f' AND FileName = '" + name + "'";
                        db.exeSQL(sql);
                    }
                    else
                    {
                        flag = false;
                    }
                    sendCycle(clients[i], &flag, 1);
                }
                else if ("quit" == order)
                {
                    ev.data.fd = clients[i];
                    ret = epoll_ctl(epfd, EPOLL_CTL_DEL, clients[i], &ev);
                    ERROR_CHECK(ret, -1, "epoll_ctl");
                    clients.erase(remove(clients.begin(), clients.end(), clients[i]), clients.end());
                    myTimer.deleteFd(clients[i]);
                    close(clients[i]);
                }
            }
            myTimer.update(clients[i]);
        }

        if (timeout) {
            timer_handler();
            timeout = false;
        }
    }
    close(sockfd);
    close(epfd);
    return 0;
}
