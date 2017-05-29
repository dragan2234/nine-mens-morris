

class Node(object):
    def __init__(self, value=0, table=[], remove=0, children=None, parents=None):
        self.value = value
        self.table = table
        self.remove = remove
        self.children = []
        self.parents = parents
        if children is not None:
            for child in children:
                self.add_child(child)

    def add_child(self, node):
        assert isinstance(node, Node)
        self.children.append(node)
        node.parents = self


def tabela(tabla): #ispisuje tablu na ekran nakon svakog poteza, tabla je lista  charova ("O"-slobodno, "A"-covek,  "B"-komp)
    print tabla[0] + "(a)----------------------" + tabla[1] + "(b)----------------------" + tabla[2] + "(c)"
    print("|                           |                          |");
    print("|                           |                          |");
    print("|       " + tabla[3] + "(d)--------------" + tabla[4] + "(e)--------------" + tabla[5] + "(f)       |");
    print("|       |                   |                  |       |");
    print("|       |                   |                  |       |");
    print("|       |        " + tabla[6] + "(g)-----" + tabla[7] + "(h)-----" + tabla[8] + "(i)        |       |");
    print("|       |         |                   |        |       |");
    print("|       |         |                   |        |       |");
    print(tabla[9] + "(j)---" + tabla[10] + "(k)----" + tabla[11] + "(l)                  " + tabla[12] + "(m)------" + tabla[13] + "(n)---" + tabla[14] + "(o)");
    print("|       |         |                   |        |       |");
    print("|       |         |                   |        |       |");
    print("|       |        " + tabla[15] + "(p)-----" + tabla[16] + "(r)-----" + tabla[17] + "(s)        |       |");
    print("|       |                   |                  |       |");
    print("|       |                   |                  |       |");
    print("|       " + tabla[18] + "(t)--------------" + tabla[19] + "(u)--------------" + tabla[20] + "(v)       |");
    print("|                           |                          |");
    print("|                           |                          |");
    print(
        tabla[21] + "(w)----------------------" + tabla[22] + "(z)----------------------" + tabla[23] + "(x)");


def Igra(p):
    print "Ko igra prvi?"
    print "1. Covek"
    print "2. Racunar"
    w = eval(raw_input(">>>"))
    while (1 > w or w > 2):
        print "Greska, pokusajte ponovo"
        w = eval(raw_input(">>>"))
    tabela(p)

    p = list(prva_faza(p, w))
    druga_faza(p, w)


def prva_faza(p, w):
    print "--------------------"
    print ">>>>>> FAZA 1 <<<<<<"
    print "--------------------"
    if w == 1:
        for i in range(9):
            q = 0
            humanturn = settingpieces(p)  # postavlja zeton, vraca string unosa broj-slovo
            if inmill(p, recnikunosa[humanturn], "P") == True:  # ako je sklopio micu, bira da se rimuvuje protivnikov
                remove_zeton(p)  # rimuvuje protivnikov
                q = -1
            p = list(prva_faza_racunar(p, q))  # stanje tab  le nakon postavljanja
    else:
        for i in range(9):
            if i == 0:
                q = 0
            p = list(prva_faza_racunar(p, q))  # prvo odigra racunar, promeni se stanje table
            humanturn = settingpieces(p)  # onda odigra covek, vraca string koordinate polja
            if inmill(p, recnikunosa[humanturn], "P") == True:
                remove_zeton(p)
                q = -1  # q je verovatno broj mica koji treba oduzeti. u funkciji
            else:  # vraca se q na nulu
                q = 0
    return p


def druga_faza(p, w):
    print "--------------------"
    print ">>>>>> FAZA 2 <<<<<<"
    print "--------------------"
    if podheuristika_num_8(p) != 0:
        win(p)  # neko je pobedio ako je rezultat podheuristike -1 ili 1
    if (w == 1):  # ako igra prvo covek
        while (True):  # sta.....ovo ce uvek vrteti
            q = 0
            humanturn1, humanturn2 = pomeranje(p)
            if inmill(p, recnikunosa[humanturn2], "P") == True:
                q = -1  # rimuvuje se kompu zeton
                remove_zeton(p)  # to se obavlja ovde
            p = list(druga_faza_racunar(p, q))  # racunarov potez
            if podheuristika_num_8(p) != 0:  # provera da li je pobedio neko od njih
                win(p)
    else:  # ako igra prvo komp
        q = 0
        while (True):
            p = list(druga_faza_racunar(p, q))  # prvo igra komp
            humanturn1, humanturn2 = pomeranje(p)  # onda igra covek
            if inmill(p, recnikunosa[humanturn2], "P") == True:
                q = -1
                remove_zeton(p)  # rimuvuje se zeton
            else:
                q = 0  # vraca se q na nulu
            if podheuristika_num_8(p) != 0:  # provera pobede
                win(p)


def win(p):
    if numbersofpieces(p, "V") < 3 or blokirani(p, "V") == True:
        print ("Pobeda!")
    else:
        print ("Poraz")
    quit()


def prva_faza_racunar(p, q):
    print "\nProtivnik je na potezu"
    racunar1 = Node(-12345, p, q)  # cvor, koren, -12345 je za max heuristiku, kad je racunar na potezu.
    lista1 = []
    p0 = []
    value = -12345
    for j in range(24):  # RACUNAROVI POTEZI
        if p[j] == "O":  # pitam se redom za svako polje da li je prazno
            pomoc1 = list(p)  # kopija, nova tabla
            pomoc1[j] = "V"  # u kopiju upisuje potez
            lista1.append(Node(12345, pomoc1,
                               0))  # LISTA CVOROVA #sve moguce poteze dodaje u listu poteza, lista1. 12345 korisnik na potezu, gleda se min heuristika
            racunar1.add_child(lista1[-1])  # dodaje potez kao dete
            if inmill(pomoc1, j, "V") == True:  # ako je u jednom od mogucih poteza mica za racunar
                lista1[-1].remove = 1  # zapise da tu moze da rimuvuje
                u, lista1[-1].table = findingmaxremoving1(pomoc1, lista1[-1])  # nalazi maxracuna heuristiku

            lista2 = []
            for m in range(24):  # KORISNIKOVI POTEZI
                if lista1[-1].table[
                    m] == "O":  # Za svaki potez kompa koji je izgenerisan pita se sledeci potez ako je slobodno polje
                    p2 = list(lista1[-1].table)  # p2 je tabla, jedna od dece korena
                    p2[
                        m] = "P"  # ta tabla se popunjava korisnikovim potezom. U sustini generisu se svi moguci potezi koje korisnik moze da odigra za svaki potez koji komp moze da odigra
                    lista2.append(Node(-12345, p2,
                                       0))  # doda se to kao koren novog stabla. tj nastavlja se izgradnja prvobitnog stabla ali na drugom nivou. -12345=max heuuristika, kad je opet racunar na potezu
                    lista1[-1].add_child(lista2[-1])  # dodaje potez kao dete
                    if inmill(p2, m,
                              "P") == True:  # ako se desi da je u jednom od mogucih odgovora korisnika sklopljena mica
                        lista2[
                            -1].remove = -1  # neka vrednost neki koeficijent je -1. Ovo ce valjda uci u racunicu za heuristiku
                        u, lista2[-1].table = findingminremoving1(p2, lista2[-1])

                    lista3 = []
                    for m1 in range(24):  # OPET KOMPOVI POTEZI, KRAJ DUBINE HEURISTIKE
                        if lista2[-1].table[m1] == "O":
                            p3 = list(lista2[-1].table)  # prethodni potez
                            p3[m1] = "V"  # dodat zeton
                            lista3.append(Node(0, p3,
                                               0))  # Value 0, tabla se doda u listu tri, ne racuna dalje, zato je heuristika nula
                            lista2[-1].add_child(lista3[-1])  # dodaje se dete na prethodni potez
                            if inmill(p3, m1, "V") == True:  # ako je komp odgovorio sa micom
                                lista3[-1].value, lista3[-1].table = findingmaxremoving1(p3, lista3[
                                    -1])  # vraca se heuristika za tu tablu i ta tabla
                            else:  # alfa i beta rez
                                lista3[-1].value = heuristika_num_1(p3, lista2[-1])  # Racuna heuristiku za cvor
                            if lista2[-1].value < lista3[
                                -1].value:  # ako je heuristika oca manja od heuristike trenutnog deteta, heuristika oca postaje heuristika deteta
                                lista2[-1].value = lista3[-1].value
                            if lista3[-1].value > lista1[
                                -1].value:  # ako je heuristika deteta veca od heuristike dede, izadji iz petlja
                                break
                    if lista1[-1].value > lista2[
                        -1].value:  # ako je heuristika oca  (komp odigrao) veca od heuristike svog deteta(covek odigrao)
                        lista1[-1].value = lista2[-1].value
                    if lista2[-1].value < value:  # Da li je korisnikov potez njegov najbolji moguci (za nas najgori)
                        break
            if value < lista1[
                -1].value:  # Da li je korisnikov najbolji potez (najgori po nas) bolji od svog najboljeg (za nas najgoreg) nakon  naseg jednog poteza?
                value = lista1[-1].value  # Ovo mu je novi najgori potez
                p0 = list(lista1[-1].table)
    razlike1(p, p0)
    p = list(p0)
    tabela(p)
    return p


def druga_faza_racunar(p, q):
    print "\nProtivnik je na potezu"
    racunar1 = Node(-12345, p, q)  # komp je zatekao tablu p
    lista1 = []
    p0 = []
    value = -12345  # najbolji kompov potez
    for j in range(24):
        if p[j] == "V" and blokiran(p, j) == False:  # ako je ovo njegov zeton i moze da se pomera
            for j1 in possiblemoves[j]:  # vrti kroz sve moguce poteze
                if p[j1] == "O":  # ako je jedno od mogucih slobodno
                    pomoc1 = list(p)  # zatecena tabla
                    pomoc1[j1], pomoc1[j] = pomoc1[j], pomoc1[j1]  # zameni im vrednosti O za V, V za O ---> pomeranje :)
                    lista1.append(Node(12345, pomoc1, 0))  # dodaj moguci potez kompa u lista1
                    racunar1.add_child(lista1[-1])  # dodaj moguci potez kao dete
                    if inmill(pomoc1, j1, "V") == True:  # ako je sklopljena mica u tom mogucem potezu
                        lista1[-1].remove = 1  # ovaj neki znak gubljenja mice postavi na 1, dobro za komp
                        u, lista1[-1].table = findingmaxremoving2(pomoc1, lista1[
                            -1])  # nadji najbolji zeton koji ces eliminisati protivniku
                    if podheuristika_num_8(pomoc1) == 1:  # Pitanje da li je pobedio komp
                        razlike2(p, pomoc1)
                        tabela(pomoc1)
                        win(pomoc1)  # pobeda
                    lista2 = []
                    for m in range(24):  # dublje, potezi korisnika
                        if lista1[-1].table[m] == "P" and blokiran(lista1[-1].table,
                                                                       m) == False:  # ako polje moze da se pomeri i ako je nejgovo
                            for j2 in possiblemoves[m]:  # vrti kroz moguca pomeranja
                                if lista1[-1].table[j2] == "O":  # pitaj da li je moguce mesto pomeranja slobodno
                                    p2 = list(lista1[-1].table)  # uzmi trenutnu tabelu ako jeste
                                    p2[j2], p2[m] = p2[m], p2[
                                        j2]  # pomeri zeton m-selektovan cvor, j2-tamo gde ce ga pomeriti
                                    lista2.append(Node(-12345, p2, 0))  # dodaj u listu2
                                    lista1[-1].add_child(lista2[-1])  # dodaj dete
                                    if inmill(p2, j2, "P") == True:  # ako je mica
                                        lista2[-1].remove = -1  # flag za rimuvovanje mice od strane coveka, komp gubi
                                        u, lista2[-1].table = findingminremoving2(p2, lista2[
                                            -1])  # STA JE NAJBOLJE RIMOVOVATI KOMPU OD STRANE COVEKA tj sta je najgore po komp
                                    lista3 = []
                                    for m1 in range(
                                            24):  # za svaki korisnikov odgovor na nas odgovor opet komp odreaguje
                                        if lista2[-1].table[m1] == "V" and blokiran(lista2[-1].table, m1) == False:
                                            for j3 in possiblemoves[m1]:
                                                if lista2[-1].table[j3] == "O":
                                                    p3 = list(lista2[-1].table)
                                                    p3[m1], p3[j3] = p3[j3], p3[m1]
                                                    lista3.append(Node(0, p3, 0))
                                                    lista2[-1].add_child(lista3[-1])
                                                    if inmill(p3, j3, "V") == True:
                                                        lista3[-1].value, lista3[-1].table = findingmaxremoving2(p3,
                                                                                                                 lista3[
                                                                                                                     -1])
                                                    else:  # alfa i beta rez
                                                        lista3[-1].value = heuristika_num_2(p3, lista2[-1])
                                                    if lista2[-1].value < lista3[
                                                        -1].value:  # MISlIM DA JE OVO NALAZENJE max HEURISTIkE ZA komp
                                                        lista2[-1].value = lista3[
                                                            -1].value  # nadje max iz trece dubine, prosedi u drugu za tatu
                                                    if lista3[-1].value > lista1[
                                                        -1].value:  # ISPLATIvO, dalje ne gledaj, skracuje vreme
                                                        break
                                    if lista1[-1].value > lista2[-1].value:
                                        lista1[-1].value = lista2[-1].value
                                    if lista2[-1].value < value:  # isplativo, dalje ne gledaj
                                        break
                    if value < lista1[-1].value:
                        value = lista1[-1].value
                        p0 = list(lista1[-1].table)
    razlike2(p, p0)  # 
    p = list(p0)
    tabela(p)
    return p  # vraca funkcija odabrani potez racunara


def findingmaxremoving1(p3, node):  # FUNKCIJA VRACA TABLU I NJENU HEURISTIKU, NAJBOLJI KOMPOV POTEZ NA PRVOM NIVOU
    k = -12345
    k1 = -12345
    p0 = []
    for i in range(24):
        if possibleremoving(p3, i, "P"):  # da li je moguce rimuvovati polje (nije ako je u mici)
            p4 = list(p3)
            p4[i] = "O"  # neka tabla u kojoj je rimuvovan covekov zeton
            k1 = heuristika_num_1(p4, node)  # heuristika za njega
        if k1 > k:  # ako je veca od trenutno najvece heuristike
            p0 = list(p4)  # izabrana tabla je ta sa najvecom heuristikom
            k = k1
    return k, p0


def findingmaxremoving2(p3, node):
    k = -12345
    k1 = -12345
    p0 = []
    for i in range(24):
        if possibleremoving(p3, i, "P"):
            p4 = list(p3)
            p4[i] = "O"
            k1 = heuristika_num_2(p4, node)
        if k1 > k:
            p0 = list(p4)
            k = k1
    return k, p0


def findingminremoving1(p2,
                        node):  # FUNKCIJA VRACA TABLU I NJENU HEURISTIKU, NAJBOLJI NAJGORI COVEKOV POTEZ NA drugom NIVOU stabla
    k = 12345
    k1 = 12345
    p0 = []
    for i in range(24):
        if possibleremoving(p2, i, "V"):
            p3 = list(p2)
            p3[i] = "O"
            k1 = heuristika_num_1(p2, node)
        if k1 < k:
            p0 = list(p3)
            k = k1
    return k, p0


def findingminremoving2(p2, node):
    k = 12345
    k1 = 12345
    p0 = []
    for i in range(24):
        if possibleremoving(p2, i, "V"):
            p3 = list(p2)
            p3[i] = "O"
            k1 = heuristika_num_2(p2, node)
        if k1 < k:
            p0 = list(p3)
            k = k1
    return k, p0


def razlike1(p, pomoc1):
    for i in range(24):
        if p[i] == "O" and pomoc1[i] == "V":
            print "Protivnik je postavio figuru na polje", unosi[i]
    if numbersofpieces(p, "P") > numbersofpieces(pomoc1, "P"):
        for i in range(24):
            if p[i] == "P" and pomoc1[i] == "O":
                print "Protivnik je pojeo vasu figuru na polju", unosi[i]


def razlike2(p, pomoc1):
    t1 = 0  
    t2 = 0
    for i in range(24):
        if p[i] == "V" and pomoc1[i] == "O":
            t1 = i
        if p[i] == "O" and pomoc1[i] == "V":
            t2 = i
    print "Protivnik je pomerio svoju figuru sa polja", unosi[t1], "na polje", unosi[t2]
    if numbersofpieces(p, "P") > numbersofpieces(pomoc1, "P"):
        for i in range(24):
            if p[i] == "P" and pomoc1[i] == "O":
                print "Protivnik je pojeo vasu figuru na polju", unosi[i]


def inmill(p, i, t):
    return (p[horizontalmill[i][0]] == t and p[horizontalmill[i][1]] == t) or (
    p[verticalmill[i][0]] == t and p[verticalmill[i][1]] == t)


def allinmill(p, t):
    for i in range(24):
        if p[i] == t:
            if inmill(p, i, t) == False:
                return False
    return True


def blokiran(p, i):
    for potez in possiblemoves[i]:
        if p[potez] == "O":
            return False
    return True


def blokirani(p, k):
    for i in range(24):
        if p[i] == k:
            if blokiran(p, i) != True:
                return False
    return True


def numbersofpieces(p, t):
    k = 0
    for piece in p:
        if piece == t:
            k += 1
    return k


def heuristika_num_1(p, node):
    return 18 * podheuristika_num_1(node) + 26 * podheuristika_num_2(p) + 1 * podheuristika_num_3(p) + 9 * podheuristika_num_4(
        p) + 10 * podheuristika_num_5(p) + 7 * podheuristika_num_6(p)


def heuristika_num_2(p, node):
    return 14 * podheuristika_num_1(node) + 43 * podheuristika_num_2(p) + 10 * podheuristika_num_3(p) + 11 * podheuristika_num_4(
        p) + 8 * podheuristika_num_7(p) + 1086 * podheuristika_num_8(p)


def podheuristika_num_1(node):
    return node.parents.remove


def podheuristika_num_2(p):
    k = 0
    for mill in mills:
        if p[mill[0]] == "V" and p[mill[1]] == "V" and p[mill[2]] == "V":
            k += 1
        if p[mill[0]] == "P" and p[mill[1]] == "P" and p[mill[2]] == "P":
            k -= 1
    return k


def podheuristika_num_3(p):
    k = 0
    for i in range(24):
        if p[i] == "V":
            if blokiran(p, i) == True:
                k -= 1
        if p[i] == "P":
            if blokiran(p, i) == True:
                k += 1
    return k


def podheuristika_num_4(p):
    return numbersofpieces(p, "V") - numbersofpieces(p, "P")


def podheuristika_num_5(p):
    k = 0
    for mill in mills:
        if (p[mill[0]] == "V" and p[mill[1]] == "V" and p[mill[2]] == "O") or (
                    p[mill[0]] == "V" and p[mill[1]] == "O" and p[mill[2]] == "V") or (
                    p[mill[0]] == "O" and p[mill[1]] == "V" and p[mill[2]] == "V"):
            k += 1
        if (p[mill[0]] == "P" and p[mill[1]] == "P" and p[mill[2]] == "O") or (
                    p[mill[0]] == "P" and p[mill[1]] == "O" and p[mill[2]] == "P") or (
                    p[mill[0]] == "O" and p[mill[1]] == "P" and p[mill[2]] == "P"):
            k -= 1
    return k


def podheuristika_num_6(p):
    k = 0
    for i in range(24):
        s = p[i] + p[verticalmill[i][0]] + p[verticalmill[i][1]] + p[horizontalmill[i][0]] + p[horizontalmill[i][1]]
        if s == "VVOVO" or s == "VVOOV" or s == "VOVVO" or s == "VOVOV":
            k += 1
        if s == "PPOPO" or s == "PPOOP" or s == "POPPO" or s == "POPOP":
            k -= 1
    return k


def podheuristika_num_7(p):
    k = 0
    for i in range(24):
        if p[i] == "V" and p[verticalmill[i][0]] == "V" and p[verticalmill[i][1]] == "V" and p[
            horizontalmill[i][0]] == "V" and p[horizontalmill[i][1]] == "V":
            k += 1
        if p[i] == "P" and p[verticalmill[i][0]] == "P" and p[verticalmill[i][1]] == "P" and p[
            horizontalmill[i][0]] == "P" and p[horizontalmill[i][1]] == "P":
            k -= 1
    return k


def podheuristika_num_8(p):  # win heuristika_num_
    if numbersofpieces(p, "V") < 3 or blokirani(p, 'V') == True:
        return -1
    if numbersofpieces(p, "P") < 3 or blokirani(p, 'P') == True:
        return 1
    return 0


def settingpieces(p):
    k = ""
    while k == "":
        k = raw_input("Unesite validno i slobodno polje na koje zelite da postavite figuru (format broj): ")
        if k in unosi:
            if p[recnikunosa[k]] == "O":
                p[recnikunosa[k]] = "P"
            else:
                k = ""
                print "To polje je zauzeto, molimo vas pokusajte ponovo!"
        else:
            k = ""
            print "Uneli ste nevalidno polje, molimo pokusajte ponovo!"
    return k


def pomeranje(p):
    k1 = ""
    k2 = ""
    while k1 == "":
        k1 = raw_input("Unesite polje na kojoj se nalazi figura koju zelite da pomerite: ")
        if k1 in recnikunosa:
            if p[recnikunosa[k1]] != "P" or blokiran(p, recnikunosa[k1]) == True:
                k1 = ""
                print "Uneto polje je nevalidno (postoji mogucnost da ste uneli ispravno polje ali nema mogucih pomeraja za isto)," \
                      " stoga pokusajte ponovo!"
        else:
            k1 = ""
            print "Uneli ste nevalidno polje, molimo pokusajte ponovo!"
    while k2 == "":
        k2 = raw_input("Unesite polje na koje zelite da pomerite izabranu figuru: ")
        if k2 in recnikunosa:
            if recnikunosa[k2] in possiblemoves[recnikunosa[k1]]:
                if p[recnikunosa[k2]] != "O":
                    k2 = ""
                    print "Uneto polje nije slobodno, molimo pokusajte ponovo!"
            else:
                k2 = ""
                print "Nije moguc pomeraj na dato polje, molimo pokusajte ponovo!"
        else:
            k2 = ""
            print "Uneto polje je nevalidno, molimo pokusajte ponovo!"
    p[recnikunosa[k1]], p[recnikunosa[k2]] = p[recnikunosa[k2]], p[recnikunosa[k1]]
    return k1, k2


def remove_zeton(p):
    tabela(p)
    k = ""
    while k == "":
        k = raw_input("Unesite validno polje sa kojeg zelite da uklonite protivnicku figuru: ")
        if possibleremoving(p, recnikunosa[k], "V"):
            p[recnikunosa[k]] = "O"
        else:
            k = ""
            print "Uneli ste nevalidno polje, molimo pokusajte ponovo!"


def possibleremoving(p, i, t):
    return p[i] == t and (allinmill(p, t) == True or inmill(p, i, t) == False)


if __name__ == "__main__":
    polja = ["O", "O", "O", "O", "O", "O", "O", "O", "O", "O", "O", "O", "O", "O", "O", "O", "O", "O", "O", "O", "O",
             "O", "O", "O"]
    recnikunosa = {"a": 0, "b": 1, "c": 2, "d": 3, "e": 4, "f": 5, "g": 6, "h": 7, "i": 8, "j": 9,
                   "k": 10, "l": 11,
                   "m": 12, "n": 13, "o": 14, "p": 15, "r": 16, "s": 17, "t": 18, "u": 19, "v": 20,
                   "w": 21, "z": 22, "x": 23}
    unosi = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l",
             "m", "n", "o", "p", "r", "s", "t", "u", "v", "w", "z", "x"]
    verticalmill = [[9, 21], [4, 7], [14, 23], [10, 18], [1, 7], [13, 20], [11, 15], [1, 4], [12, 17], [0, 21], [3, 18],
                    [6, 15], [8, 17], [5, 20], [2, 23], [6, 11],
                    [19, 22], [8, 12], [3, 10], [16, 22], [5, 13], [0, 9], [16, 19], [2, 14]]
    horizontalmill = [[1, 2], [0, 2], [0, 1], [4, 5], [3, 5], [3, 4], [7, 8], [6, 8], [6, 7], [10, 11], [9, 11],
                      [9, 10], [13, 14], [12, 14], [12, 13], [16, 17], [15, 17],
                      [15, 16], [19, 20], [18, 20], [18, 19], [22, 23], [21, 23], [21, 22]]
    mills = [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9, 10, 11], [12, 13, 14], [15, 16, 17], [18, 19, 20], [21, 22, 23],
             [0, 9, 21], [3, 10, 18], [6, 11, 15], [1, 4, 7], [16, 19, 22],
             [8, 12, 17], [5, 13, 20], [2, 14, 23]]
    humanpieces = []
    possiblemoves = [[1, 9], [0, 2, 4], [1, 14], [4, 10], [1, 3, 5, 7], [4, 13], [11, 7], [4, 6, 8], [7, 12],
                     [0, 21, 10], [3, 9, 11, 18], [6, 10, 15], [8, 13, 17],
                     [5, 12, 20, 14], [2, 13, 23], [11, 16], [15, 17, 19], [12, 16], [10, 19], [16, 18, 22, 20],
                     [13, 19], [9, 22], [21, 19, 23], [22, 14]]
    Igra(polja)