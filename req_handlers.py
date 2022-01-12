import ipaddress
from datetime import datetime
from main import ENCODING, IRC_CHAT_ADDRESS, lobbies, logging
from main import Player, Lobby
from main import leave_lobby_process, terminate_incorrect_lobbies


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
    

def new_game_create(host: Player, options):

    max_players = None
    game_type = None
    password = None
    game_title = None

    for option in options:
        option = option.strip("'")
        if option.startswith("max_players="):
            max_players = int(option[12:])+2
        elif option.startswith("type="):
            game_type = option[5:]
        elif option.startswith("password="):
            if len(option[9:]) > 1:
                password = option[9:]
        elif option.startswith("title="):
            title = option[6:]
    
    #Handling missing arguments - Probably unnecessary.
    if None in [max_players,game_type,password,title]:
        return bytearray()

    new_lobby_id = len(lobbies)+1
    host.hosting_lid = new_lobby_id
    host.lobby_id = new_lobby_id
    lobbies[new_lobby_id] = Lobby(host=host,
                                  max_players=max_players,
                                  password=password,
                                  game_title=game_title,
                                  lobby_id=new_lobby_id,
                                  game_type=game_type)
    newgamestring = open(f"res/new_game_dlg_create.dcml", "rb").read()
    newgamestring = newgamestring.decode(ENCODING)
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
            leave_lobby_process(client)
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
    """Handles dbtbl (available lobby table) calls."""
    terminate_incorrect_lobbies()
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
        pingstringtemp = pingstringtemp.replace("GAMETYPE", lobj.game_type)
        pingstringtemp = pingstringtemp.replace("CURRENT_PLAYERS", str(lobj.players))
        pingstringtemp = pingstringtemp.replace("MAX_PLAYERS", str(lobj.max_players))
        currlobby += 1
        pingstring += pingstringtemp
    newlobbystring = newlobbystring.replace("//BUTTONSTRING", buttonstring)
    newlobbystring = newlobbystring.replace("//PINGSTRING", pingstring)
    return newlobbystring


def new_game_dlg(client: Player, options: list):
    delete_old = None
    for option in options:
        option = option.strip("'")
        if option.startswith("delete_old="):
            delete_old = option[11:]
    if delete_old == 'true':
        leave_lobby_process(client)
    response_data = data_from_file("new_game_dlg.dcml")
    response_data = response_data.replace("NICKNAME", client.player_name)
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
            payload = "log_user_bad.dcml"
        response_data = data_from_file("log_user.dcml")
        response_data = response_data.replace("NICKNAME", client.player_name)
        response_data = response_data.replace("PLAYERID", str(client.session_id))
        response_data = response_data.replace("CHAT_ADDRESS", IRC_CHAT_ADDRESS)