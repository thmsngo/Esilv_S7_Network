from datetime import date,datetime
import sqlite3

def logs(request):
    logList=[]
    try:
        conn = sqlite3.connect('logserver.db')
        cur = conn.cursor()
        #Display all logs
        if request=="all":
            cur.execute("SELECT macSrc,request FROM logs")
            
        #Display logs of the day
        elif request=="day":
            sql="SELECT macSrc,request FROM logs WHERE date=?"
            value=(str(date.today()),)
            cur.execute(sql,value)
            
        #Display DNS logs
        elif(request=="dns"):
            cur.execute("SELECT macSrc,request FROM logs WHERE portSrc=53 or portDst=53")
            
        #Display DHCP logs
        elif(request=="dhcp"):
            cur.execute("SELECT macSrc,request FROM logs WHERE portSrc=67 or portSrc=68 "+
                        "or portDst=67 or portDst=68")
            
        logList = cur.fetchall()
        cur.close()
    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (conn):
            conn.close()
    return logList

def sortedlogs(request):
    logList=[]
    try:
        conn = sqlite3.connect('logserver.db')
        cur = conn.cursor()
        #Sort Logs By IP
        if request=="IP":
            cur.execute("SELECT macSrc,request,IPSrc FROM logs ORDER BY IPSrc")
            
        #Sort Logs By Date
        elif request=="Date":
            cur.execute("SELECT macSrc,request,date FROM logs ORDER BY date")
            
        #Sort Logs By Time
        elif(request=="Time"):
            cur.execute("SELECT macSrc,request,time FROM logs ORDER BY time")
        
        logList = cur.fetchall()
        cur.close()
    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (conn):
            conn.close()
    return logList



if __name__== '__main__' :
    print("DNS DHCP Log server")
    run=True
    while run:
        rep=input("1/Afficher les logs du jour\n"+
                  "2/Afficher tous les logs\n"+
                  "3/Afficher les requêtes DNS\n"+
                  "4/Afficher les requêtes DHCP\n"+
                  "5/Afficher les logs triés (ip, date & time)\n")
        if(rep=="1"):
            logList=logs("day")
            for record in logList:
                print(record[0]+" : "+record[1])
        elif(rep=="2"):
            logList=logs("all")
            for record in logList:
                print(record[0]+" : "+record[1])
        elif (rep=="3"):
            logList=logs("dns")
            for record in logList:
                print(record[0]+" : "+record[1])
        elif(rep=="4"):
            logList=logs("dhcp")
            for record in logList:
                print(record[0]+" : "+record[1])
        elif(rep=="5"):
            tri=input("1/Par IP\n2/Par Date\n3/Par Heure\n")
            logList=[]
            if tri=="1" :logList=sortedlogs("IP")
            elif tri=="2" :logList=sortedlogs("Date")
            elif tri=="3" :logList=sortedlogs("Time")
            for record in logList:
                print(record[0]+" : "+record[1]+" ("+record[2]+")")
        val=input("Continuer?(y/n)")
        if val!="y":
            run=False
            
            
            
            
            
            
            
            
        