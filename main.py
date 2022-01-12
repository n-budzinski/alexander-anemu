import socket, math, errno
import threading, ipaddress
import struct
import zlib
import logging
from datetime import datetime


sessions = {}
connections = []  # Player objects
lobbies = {}  # lobby_id : Lobby

total_connections = 0
connection_count = 0
lobby_count = 0

ENDIANNESS = "little"
ENCODING = "utf-8"

HOST = '0.0.0.0'
IRC_CHAT_ADDRESS = "alexander-chat.hardko.de"

TCP_PORT = 34001
TCP_TIMEOUT = 120
UDP_PORT = 34000

GGWDSERVER_LANG = 0
GGWDSERVER_VERS = 16



GAME_TYPES = {
                "0": "Normal",
                #"1": "Event",
            }




class Player(threading.Thread):

    def __init__(self, _socket, ip_address, session_id, player_name='Player'):
        threading.Thread.__init__(self)
        self.sock = _socket
        self.ip_address = ip_address
        self.session_id = session_id
        self.player_name = player_name
        self.lobby_id = -1
        self.packet_ordinal = 1
        self.hosting_lid = -1
        #self.packet_ordinal = 1
        #self.game_version = 0

    def __str__(self):
        return str(self.session_id) + " " + str(self.ip_address)

    def remove(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
            leave_lobby_process(self)
            connections.remove(self)

        except OSError.errno == errno.ENOTCONN:
            logging.debug("Tried shutting down disconnected endpoint")

    def run(self):

        self.sock.setblocking(1)
        self.sock.settimeout(TCP_TIMEOUT)

        while True:

            try:
                print(len(connections))
                data = self.sock.recv(512)

            except socket.timeout:
                logging.info(f"{str(self.ip_address)} timed out")
                self.remove()
                break

            except ConnectionError:
                logging.info(f"{str(self.ip_address)} has disconnected due to a connection error")
                self.remove()
                break

            except OSError:
                pass

            except:
                logging.info(f"{str(self.ip_address)} has disconnected")
                self.remove()
                break

            else:

                if data:

                    try:

                        response = processrequest(data, self)

                        # Breaking down large packets - Default value used by the original master server = 1440
                        fragment_offset = 0
                        for fragment_i in range(0, math.ceil(len(response)/1440)):
                            fragment = response[fragment_offset:fragment_offset + 1440]
                            fragment_offset = (fragment_i + 1) * 1440
                            self.sock.send(fragment)

                    except Exception as exception:
                        logging.critical(f"{str(self.ip_address)} caused an unexpected error. \n",
                                         f"- - - - - - - - - - - - - - - - - - - - - - - - - -\n",
                                         f"{data}",
                                         f"- - - - - - - - - - - - - - - - - - - - - - - - - -\n")
                        self.remove()
                        break
                else:
                    self.sock.send(bytearray())


class Lobby:

    def __init__(self, host, max_players, password, game_title, lobby_id, game_type="Normal"):
        self.host = host
        self.players = 1
        self.max_players = max_players
        self.game_type = game_type
        self.password = password
        self.game_title = game_title
        self.lobby_id = lobby_id
        self.ip_address = host.ip_address


def data_from_file(filename: str):
    return open(f'res/{filename}', 'rb').read().decode('utf-8')


def check_sanitized(text: str):
    if text.isalnum() and text[0].isalpha():
        return True
    return False

def reverseip(address: str):
    address = address[0].split(".")
    address = [octet for octet in address[::-1]]
    address = ".".join(address)
    return str(int(ipaddress.IPv4Address(address)))
    

def leave_lobby_process(client: Player):
    print("leave lobby called")
    try:
        if client.lobby_id in lobbies:
            del lobbies[client.lobby_id]
        if client.hosting_lid in lobbies:
            del lobbies[client.hosting_lid]
    except KeyError:
        logging.warning("Cannot remove the lobby. It doesn't exist!")
    except Exception:
        print(Exception)
    client.lobby_id = -1
    client.hosting_lid = -1


def terminate_incorrect_lobbies():
    print(len(connections))
    for lobby in lobbies:
        if lobbies[lobby].host not in connections:
            logging.warning("A lobby is missing its host. Removing...")
            del lobbies[lobby]


# TODO Research the behavior when multiple commands are present

def data_deconstruct(inputdata):
    functions = []
    fun_count = struct.unpack("B", inputdata[0:1])[0]
    #fun_count = int.from_bytes(inputdata[0:2], ENDIANNESS)  # number of functions in the packet (usually 1)
    for function_n in range(0, fun_count):
        parameter_length = 0
        function_length = struct.unpack_from("B", inputdata[2:3], False)[0]
        cursor = 5 + function_length
        functions.append([inputdata[3:3 + function_length].decode(ENCODING), []])  # requested function
        param_n = struct.unpack("B", inputdata[3 + function_length:4+ function_length])[0]  #  quantity of parameters
        for entry in range(0, param_n):
            buffer = inputdata[cursor:cursor+2]
            parameter_length = struct.unpack("<H", inputdata[cursor:cursor+2],)[0]
            cursor += 4
            value = inputdata[cursor:cursor+parameter_length-1]
            functions[function_n][1].append(value)
            cursor += parameter_length
        inputdata = inputdata[cursor:]
    return functions


def data_construct(data, magicbytes):
    # first entry is action
    packet = bytearray()
    packet.extend(struct.pack("H", data.__len__()))  # number of functions in the packet
    fn = 0
    for function in data:
        data[fn].append(magicbytes)
        #data[fn].append("21")
        packet.extend(struct.pack("B", data[fn][0].__len__()))  # function length
        packet.extend(data[fn][0].encode(ENCODING))  # function name
        packet.extend(struct.pack("H", data[fn].__len__()-1))  # param count ?(don't count the function)
        for parameter in function[1:]:
            packet.extend(struct.pack("H", len(parameter)))
            packet.extend([0x00, 0x00])
            packet.extend(parameter.encode(ENCODING))
        fn += 1
    return packet

def packet_pack(packet, request):
    datalen = len(packet)
    packeddata = zlib.compress(packet)
    finalizedpacket = bytearray()
    finalizedpacket.extend(request[:2])  # packet ordinal
    finalizedpacket.extend(struct.pack("B", GGWDSERVER_LANG))  # client language
    finalizedpacket.extend(struct.pack("B", GGWDSERVER_VERS))  # client game
    finalizedpacket.extend(struct.pack("I", len(packeddata) + 12))  # data + header size
    finalizedpacket.extend(struct.pack("I", datalen))  # unpacked data length
    finalizedpacket.extend(packeddata)
    return finalizedpacket



def new_game_create(host: Player, options):
    max_players = None
    game_type = None
    game_password = None
    game_title = None

    for option in options:
        option = option.strip("'")
        if option.startswith("max_players="):
            max_players = int(option[12:])+2
            if max_players > 7:
                max_players = 7
        elif option.startswith("type="):
            game_type = option[5:]
            if game_type not in GAME_TYPES:
                game_type = GAME_TYPES[0]
        elif option.startswith("password="):
            if len(option[9:]) > 1:
                game_password = option[9:]
            else:
                game_password = ""
        elif option.startswith("title="):
            game_title = option[6:]
            if len(game_title) < 3:
                return data_from_file("new_game_dlg.dcml")
    
    #Handling missing arguments - Probably unnecessary.
    if None in [max_players,game_type,game_password,game_title]:
        return data_from_file("cancel.dcml")

    new_lobby_id = len(lobbies)+1
    host.hosting_lid = new_lobby_id
    host.lobby_id = new_lobby_id
    lobbies[new_lobby_id] = Lobby(host=host,
                                  max_players=max_players,
                                  password=game_password,
                                  game_title=game_title,
                                  lobby_id=new_lobby_id,
                                  game_type=game_type)
    newgamestring = data_from_file("new_game_dlg_create.dcml")
    newgamestring = newgamestring.replace("MAXPLAYERS", str(max_players))
    newgamestring = newgamestring.replace("LOBBYID", str(new_lobby_id))
    newgamestring = newgamestring.replace("GAMETITLE", game_title)
    return newgamestring


def join_game(client, options):
    
    lobby = None
    delete_old = False
    lobby_id = None
    password = None

    for option in options:
        option = option.strip("'")
        if option.startswith("delete_old="):
            delete_old = option[11:]
        elif option.startswith("id_room="):
            lobby_id = option[8:]
        elif option.startswith("password="):
            if len(option[9:])>1:
                password = option[9:]

    if lobby is not None:
        #if len(lobby.players) >= lobby.max_players:
        if lobby.players == lobby.max_players:
            newlobbystring = data_from_file("lobby_full.dcml")
            return newlobbystring
        elif lobby.host.session_id == client.session_id:
            newlobbystring = data_from_file("join_game_own.dcml")
            newlobbystring = newlobbystring.replace("LOBBY_ID", lobby_id)
            return newlobbystring
        else:
            if lobby.password is not None:
                if password is None:
                    newlobbystring = data_from_file("password_prompt.dcml")
                    newlobbystring = newlobbystring.replace("LOBBYID", lobby_id)
                    return newlobbystring
                elif password != lobby.password:
                        newlobbystring = data_from_file("incorrect_password.dcml")
                        return newlobbystring
            client.lobby_id = lobby_id
            requested_lobby = lobbies[int(lobby_id)]
            newlobbystring = data_from_file("join_game.dcml")
            newlobbystring = newlobbystring.replace("LOBBYID", lobby_id)
            newlobbystring = newlobbystring.replace("MAXPLAYERS", str(requested_lobby.max_players))
            newlobbystring = newlobbystring.replace("GAMEHOST", requested_lobby.host.player_name)
            newlobbystring = newlobbystring.replace("IPADDR", requested_lobby.ip_address[0])
            newlobbystring = newlobbystring.replace("PORT", str(34000))

    else:
        newlobbystring = data_from_file("join_game_incorrect.dcml")
        newlobbystring = newlobbystring.replace("LOBBY_ID", lobby_id)

    return newlobbystring


def get_dbtbl(options: list):
    #print(len(main.lobbies))
    #print(len(main.connections))
    """Handles dbtbl (available lobby table) calls."""
    #main.terminate_incorrect_lobbies()
    order = None
    resort = None
    for option in options:
        option = option.strip("'")
        if option.startswith("order="):
            order = option[6:]
        elif option.startswith("resort="):
            resort = option[7:]

    lastupdate = datetime.now()
    lastupdate = lastupdate.strftime("%H:%M:%S")
    entrypos = 0
    currlobby = 0
    buttonstring = ""
    pingstring = ""
    newlobbystring = data_from_file("dbtbl.dcml")
    newlobbystring = newlobbystring.replace("//LASTUPDATE", lastupdate)
    for (lid, lobj) in lobbies.items():
        buttonstringtemp = "#apan[%APANLOBBYN](%SB[x:0,y:ENTRYPOS-2,w:100%,h:20]," \
                           "{GW|open&join_game.dcml\\00&delete_old=true^id_room=LOBBYID\\00|LW_lockall},8) " \
                      "#font(BC12,BC12,BC12)" \
                      "#ping[%PINGLOBBYN](%SB[x:86%+30,y:ENTRYPOS+4,w:14,h:20],IPADDR)"
        buttonstringtemp = buttonstringtemp.replace("ENTRYPOS", str(entrypos))
        buttonstringtemp = buttonstringtemp.replace("LOBBYID", str(lid))
        buttonstringtemp = buttonstringtemp.replace("IPADDR", reverseip(lobj.ip_address))
        buttonstringtemp = buttonstringtemp.replace("LOBBYN", str(currlobby))
        buttonstring += buttonstringtemp
        entrypos += 21
        pingstringtemp = ''',21,"GAMETITLE","GAMEHOST","GAMETYPE","CURRENT_PLAYERS/MAX_PLAYERS",""'''
        pingstringtemp = pingstringtemp.replace("GAMETITLE", lobj.game_title)
        pingstringtemp = pingstringtemp.replace("GAMEHOST", lobj.host.player_name)
        pingstringtemp = pingstringtemp.replace("GAMETYPE", GAME_TYPES[lobj.game_type])
        pingstringtemp = pingstringtemp.replace("CURRENT_PLAYERS", str(lobj.players))
        pingstringtemp = pingstringtemp.replace("MAX_PLAYERS", str(lobj.max_players))
        currlobby += 1
        pingstring += pingstringtemp
    newlobbystring = newlobbystring.replace("//BUTTONSTRING", buttonstring)
    newlobbystring = newlobbystring.replace("//PINGSTRING", pingstring)
    return newlobbystring


def new_game_dlg(client: Player, options: list):
    #main.leave_lobby_process(client)
    delete_old = None
    for option in options:
        option = option.strip("'")
        if option.startswith("delete_old="):
            delete_old = option[11:]
    #if delete_old == 'true':
        #leave_lobby_process(client)
    response_data = data_from_file("new_game_dlg.dcml")
    response_data = response_data.replace("NICKNAME", client.player_name)
    types = []
    for type in GAME_TYPES:
        types.append(f"{GAME_TYPES[type]},")
    response_data = response_data.replace("//TYPES", "".join(types))
    return response_data

def voting(options: list):
    question = None
    answer = None
    for option in options:
        option = option.strip("'")
        if option.startswith("question="):
            question = option[9:]
        elif option.startswith("answer="):
            answer = option[7:]
    response_data = data_from_file("voting.dcml")
    return response_data

def log_user(client, options):
        ve_nick = None
        for option in options:
            option = option.strip("'")
            if option.startswith("VE_NICK="):
                ve_nick = option[8:]
        client.player_name = ve_nick
        if len(client.player_name) < 3 or not check_sanitized(client.player_name):
            return data_from_file("log_user_bad.dcml")
        response_data = data_from_file("log_user.dcml")
        response_data = response_data.replace("NICKNAME", client.player_name)
        response_data = response_data.replace("PLAYERID", str(client.session_id))
        response_data = response_data.replace("CHAT_ADDRESS", IRC_CHAT_ADDRESS)
        return response_data




def processrequest(raw_data, client: Player):

    terminate_incorrect_lobbies()

    response_parameters = []

    datanoheader = zlib.decompress(raw_data[12:])

    data = data_deconstruct(datanoheader)
    reqfunction = data[0][0]
    parameters = data[0][1]
    request = parameters[0].decode(ENCODING)

    #Default action
    retaction = "LW_show"

    #print(parameters)
    #print(reqfunction)
    print(f"{client.ip_address}{data}")

    magic_bytes = parameters[len(parameters) - 2].decode(ENCODING)
    
    if client.session_id == b'0':
        client.session_id = int(parameters[len(parameters)-1])

    #Sent when creating a lobby
    if reqfunction == "setipaddr":
        return bytearray()

    #Sent when leaving a lobby
    elif reqfunction == "leave":
        leave_lobby_process(client)
        return bytearray()

    #Sent when starting a game (?)
    elif reqfunction == "start":
        return bytearray()

    #Requested when opening an URL
    elif reqfunction == "url":
        retaction = "LW_time"
        returl = "open:" + parameters[0].decode('utf8')
        responsedata = data_construct([[retaction, "0", returl]], parameters[len(parameters) - 2].decode('utf8'))
        return packet_pack(responsedata, raw_data)

    #Sent periodically during the game (?)
    elif reqfunction == "gmalive":
        return bytearray()

    #Sent periodically during the game (?)
    elif reqfunction == "stats":
        return bytearray()

    #Sent after a finished game
    elif reqfunction == "endgame":
        leave_lobby_process(client)
        return bytearray()
    
    #Sent periodically as a lobby keep-alive
    elif reqfunction == "alive":
        if client.lobby_id in lobbies:
            lobbies[client.lobby_id].players = int.from_bytes(parameters[0][0:1], 'little')
        return bytearray()

    #Sent while logging in
    elif reqfunction == "login":
        leave_lobby_process(client)
        payload = "demologin.dcml"
        response_data = data_from_file(payload)
        response_parameters.append([retaction, response_data])

    elif reqfunction == "open":

        options = parameters[1].decode(ENCODING).split(sep="^")

        #Requested when joining the game for the first time. Contains the IRC host and others.
        if request == "log_user.dcml":
            response_data = log_user(client, options)
            response_parameters.append([retaction, response_data])

        #Don't remember :v)
        elif request == "log_conf_dlg.dcml":
            response_data = data_from_file(request)
            response_parameters.append([retaction, response_data])

        #Requested periodically to get the current lobby list.
        elif request == "dbtbl.dcml":
            response_data = get_dbtbl(options)
            response_parameters.append([retaction, response_data])

        #Self explanatory
        elif request == "cancel.dcml":
            response_data = data_from_file(request)
            response_parameters.append([retaction, response_data])

        #Requested when joining the game for the first time. Contains the basic UI layout.
        elif request == "startup.dcml":
            response_data = data_from_file(request)
            response_parameters.append([retaction, response_data])

        #Requested periodically to get the current voting status.
        elif request == "voting.dcml":
            response_data = voting(options)
            response_parameters.append([retaction, response_data])
        
        #Requested when joining the game for the first time (?). Basically the same as "dbtbl.dcml"
        elif request == "games.dcml":
            response_data = get_dbtbl(options)
            response_parameters.append([retaction, response_data])
        
        #Requested when the the lobby is chosen
        elif request == "join_game.dcml":
            leave_lobby_process(client)
            responsedata = join_game(client, options)
            response_parameters.append([retaction, responsedata])

        #Requested after clicking the "Create" button
        elif request == "new_game_dlg.dcml":
            leave_lobby_process(client)
            response_data = new_game_dlg(client, options)
            response_parameters.append([retaction, response_data])

        #Requested when creating a new lobby (after the new_game_dlg.dcml dialog)
        elif request == "new_game_dlg_create.dcml":
            leave_lobby_process(client)
            responsedata = new_game_create(client, options)
            response_parameters.append([retaction,responsedata])
            return packet_pack(data_construct(response_parameters, magic_bytes), raw_data)

        else:
            response_data = data_from_file("cancel.dcml")

    else:
        pass

    return packet_pack(data_construct(response_parameters, magic_bytes), raw_data)


def handleclient(recvdata, recvaddr, keepalivesock):

    datalen = len(recvdata)
    action_id = recvdata[4]

    # Responds with a public IP address of the client
    if action_id == 22:
        publicaddr = bytearray()
        publicaddr.extend(recvdata[:4])
        publicaddr.extend(struct.pack('H', 17))
        octets = recvaddr[0].split(sep=".")
        for octet in octets:
            octetint = int(octet)
            octetint = struct.pack("B", octetint)
            publicaddr.extend(octetint)
        clientport = struct.pack("H", recvaddr[1])
        publicaddr.extend(clientport)
        keepalivesock.sendto(publicaddr, recvaddr)

    # Relays client network interfaces to the provided lobby host
    elif action_id == 24:
        hostaddr = recvdata[6:10]
        hostaddr = [str(byte) for byte in hostaddr]
        hostaddr = ".".join(hostaddr)
        for lobby in lobbies:
            if hostaddr == lobbies[lobby].host.ip_address[0]:
                recvdata = bytearray(recvdata)
                recvdata[-5:] = [0x25, 0xCD, 0x40, 0x6E, 0x3E]
                keepalivesock.sendto(recvdata, (hostaddr, 34000))

    #
    # CLIENT - > SERVER
    #
    #   (pCSG)    (ACTION ID)   00   (CLIENT IP)  (PORT) (N-ADAPTERS)(ADAPTER-1)  (ADAPTER-2)  (ADAPTER-3)  (PADDING)
    # 70 43 53 47     18        00   25 78 C0 5E   84D0       03     AC 19 B0 01  0A 88 48 C4  C0 A8 01 C8
    #
    # SERVER - > HOST
    #
    #   (pCSG)    (ACTION ID)   00   (CLIENT IP)  (PORT) (N-ADAPTERS)(ADAPTER-1)  (ADAPTER-2)  (ADAPTER-3)  (PADDING)
    # 70 43 53 47     18        00   D9 8A C2 42   84D0       03     AC 19 B0 01  0A 88 48 C4  C0 A8 01 C8
    #

    else:
        logging.warning(msg=f"Unknown UDP data (length of {datalen}): {recvdata}")


def tcp_connections(tcp_sock):
    global total_connections, connections
    while True:
        sock, address = tcp_sock.accept()
        connections.append(Player(sock, address, total_connections+1))
        connections[len(connections) - 1].start()
        logging.info(f"New connection at {str(connections[len(connections) - 1])}")
        total_connections += 1


def udp_connections(udp_sock):
    while True:
        recvdata, recvaddr = udp_sock.recvfrom(64)
        keepalivethread = threading.Thread(target=handleclient, args=(recvdata, recvaddr, udp_sock))
        keepalivethread.start()


def main():

    logging.info(msg="Init START")

    # MASTER SERVER HANDLER
    tcpsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpsocket.bind((HOST, TCP_PORT))
    tcpsocket.settimeout(None)
    tcpsocket.listen(20)

    master_thread = threading.Thread(target=tcp_connections, args=(tcpsocket,))
    master_thread.start()

    # LOBBY HANDLER
    udpsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpsocket.bind((HOST, UDP_PORT))
    udpsocket.setblocking(True)

    lobby_thread = threading.Thread(target=udp_connections, args=(udpsocket,))
    lobby_thread.start()

    logging.info(msg="Init OK")


if __name__ == "__main__":
    logging.basicConfig(format="%(asctime)s %(message)s", level=logging.DEBUG)
    main()







