from mysql_honeypot import MySqlHoneypot


def test_connect_mysql_honeypot():
    honeypot = MySqlHoneypot()
    honeypot.start()

    # connect to mysql honeypot


    honeypot.stop()
