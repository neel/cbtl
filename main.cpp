#include <iostream>
#include <array>
#include <string>
#include <zmq.hpp>
#include "crn.h"

int main(int argc, char** argv) {
    zmq::context_t context (2);
    zmq::socket_t socket (context, zmq::socket_type::rep);
    socket.bind ("tcp://*:5555");
    while (true) {
        zmq::message_t request;

        //  Wait for next request from client
        auto res = socket.recv(request, zmq::recv_flags::none);
        if(res){
            std::cout << "Received " << request << std::endl;
        }

        //  Send reply back to client
        zmq::message_t reply (5);
        memcpy(reply.data (), "World", 5);
        socket.send (reply, zmq::send_flags::none);
    }
    return 0;
}
