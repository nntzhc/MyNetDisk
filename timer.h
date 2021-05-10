#include "function.h"
#include <unordered_map>
#include <time.h>
#include <netinet/in.h>

class tw_timer;

//单个定时器单元
class tw_timer
{
public:
    tw_timer(int rot, int ts)
        : next(NULL), prev(NULL), rotation(rot), time_slot(ts) {}

public:
    int rotation;
    int time_slot;
    void (*cb_func)(int*);
    int* UserSocket;
    tw_timer* next;
    tw_timer* prev;
};

class Timer
{
public:
    Timer() : cur_slot(0)
    {
        for (int i = 0; i < N; ++i)
        {
            slots[i] = NULL;
        }
    }
    ~Timer()
    {
        for (int i = 0; i < N; ++i)
        {
            tw_timer* tmp = slots[i];
            while (tmp)
            {
                slots[i] = tmp->next;
                delete tmp;
                tmp = slots[i];
            }
        }
    }

    //有新的客户端连接上
    void add(const int &fd, int timeout=60)
    {
        if (timeout < 0)
        {
            return NULL;
        }
        int ticks = 0;
        if (timeout < TI)
        {
            ticks = 1;
        }
        else
        {
            ticks = timeout / TI;
        }
        int rotation = ticks / N;
        int ts = (cur_slot + (ticks % N)) % N;
        tw_timer* timer = new tw_timer(rotation, ts);
        int* Fd = new(int); *Fd = fd;
        timer->UserSocket = Fd;
        Soc2Time[fd] = timer;

        if (!slots[ts])
        {
            printf("add timer, rotation is %d, ts is %d, cur_slot is %d\n", rotation, ts, cur_slot);
            slots[ts] = timer;
        }
        else
        {
            timer->next = slots[ts];
            slots[ts]->prev = timer;
            slots[ts] = timer;
        }

    }

    //客户端关闭
    void deleteFd(int fd)
    {
        tw_timer* timer = Soc2Time[fd];
        Soc2Time.erase(fd);
        if (!timer)
        {
            return;
        }
        int ts = timer->time_slot;
        if (timer == slots[ts])
        {
            slots[ts] = slots[ts]->next;
            if (slots[ts])
            {
                slots[ts]->prev = NULL;
            }
            delete timer;
        }
        else
        {
            timer->prev->next = timer->next;
            if (timer->next)
            {
                timer->next->prev = timer->prev;
            }
            delete timer;
        }
    }
    void tick()
    {
        tw_timer* tmp = slots[cur_slot];
        printf("current slot is %d\n", cur_slot);
        while (tmp)
        {
            printf("tick the timer once\n");
            if (tmp->rotation > 0)
            {
                tmp->rotation--;
                tmp = tmp->next;
            }
            else
            {
                tmp->cb_func(tmp->user_data);
                if (tmp == slots[cur_slot])
                {
                    printf("delete header in cur_slot\n");
                    slots[cur_slot] = tmp->next;
                    delete tmp;
                    if (slots[cur_slot])
                    {
                        slots[cur_slot]->prev = NULL;
                    }
                    tmp = slots[cur_slot];
                }
                else
                {
                    tmp->prev->next = tmp->next;
                    if (tmp->next)
                    {
                        tmp->next->prev = tmp->prev;
                    }
                    tw_timer* tmp2 = tmp->next;
                    delete tmp;
                    tmp = tmp2;
                }
            }
        }
        cur_slot = ++cur_slot % N;
    }

    //客户端发来数据
    void update(const int &fd)
    {
        deleteFd(fd);
        add(fd);
    }

private:
    static const int N = 60;
    static const int TI = 1;
    tw_timer* slots[N];
    int cur_slot;
    unordered_map<int, tw_timer*> Soc2Time;
};
