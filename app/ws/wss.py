'''
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation <https://kagatifoundation.github.org>
'''

import threading
import json
import websockets
import asyncio

# Sniffer library
from particle import InterfaceManager, HexParticleSniffer
from net_consts import ALL_PAYLOAD_TYPES

all_interfaces = []
interface_packet_queues = {}
connected_clients = {}

async def broadcast_packets(interface: str):
    while True:
        packet = await interface_packet_queues[interface].get()
        if interface in connected_clients:
            dead_clients = set()
            for w_sock in connected_clients[interface]:
                try:
                    await w_sock.send(json.dumps(packet))
                except:
                    dead_clients.add(w_sock)
            connected_clients[interface] -= dead_clients


def should_include_payload(filters, packet):
    if len(filters) == 0:
        return True

    payload = packet.get('Payload')
    while True:
        if payload is None:
            return False
        else:
            payload_type = payload.get('Payload Type')
            if payload_type:
                pkt_payload_type = ALL_PAYLOAD_TYPES.get(int(payload_type))
                if pkt_payload_type in filters:
                    return True
                else:
                    pass

        payload = payload.get('Payload')


def sniffer_thread(interface: str, filters_q: asyncio.Queue[str], loop):
    global interface_packet_queues

    snif = HexParticleSniffer(interface)
    filters = []

    while True:
        packet = snif.next_packet()
        if packet is not None:
            try:
                packet_json = json.loads(packet)

                try:
                    filters = filters_q.get_nowait()
                except asyncio.QueueEmpty:
                    pass

                if should_include_payload(filters, packet_json):
                    asyncio.run_coroutine_threadsafe(
                        interface_packet_queues[interface].put(packet_json),
                        loop
                    )
            except json.JSONDecodeError:
                continue


async def handle_interface_list_reqs(w_socket):
    try:
        await w_socket.send(
            json.dumps({
                "ifs": all_interfaces
            })
        )
        await w_socket.close()
    except Exception as e:
        await w_socket.close()


async def handle_packet_list_reqs(w_socket):
    filters_q = asyncio.Queue()
    interface = None
    path = w_socket.request.path

    global connected_clients
    
    if path.startswith("/if/"):
        interface = path[len("/if/"):]

    if interface is None:
        await w_socket.close()
        return

    if interface not in connected_clients:
        connected_clients[interface] = set()

    print(f"[*] Serving {interface}'s data...")

    connected_clients[interface].add(w_socket)
    if interface_packet_queues.get(interface) is None:
        interface_packet_queues[interface] = asyncio.Queue()
        loop = asyncio.get_running_loop()

        try:
            filters = filters_q.get_nowait()
        except asyncio.QueueEmpty:
            filters = []

        threading.Thread(
            target=sniffer_thread, 
            args=(interface, filters_q, loop), 
            daemon=True
        ).start()
        
        asyncio.create_task(broadcast_packets(interface))

    try:
        async for message in w_socket:
            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                continue

            if data.get("type") == "filters_update":
                await filters_q.put(data["filters"])
    finally:
        await w_socket.close()
        connected_clients[interface].remove(w_socket)


async def client_handler(w_socket):
    if w_socket.request.path == "/ifs":
        print("[*] Serving interfaces names...", end="")
        await handle_interface_list_reqs(w_socket)
        print("DONE")
    elif w_socket.request.path.startswith("/if/"):
        await handle_packet_list_reqs(w_socket)
    else:
        await w_socket.close()

    
async def main():
    global all_interfaces
    try:
        interface_mgr = InterfaceManager()
        all_interfaces = interface_mgr.get_all_interface_names()
    except Exception as e:
        raise e

    server = await websockets.serve(client_handler, '127.0.0.1', 12346)
    await server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
        print("[*] Analyzer started...")
    except KeyboardInterrupt as e:
        print(e)