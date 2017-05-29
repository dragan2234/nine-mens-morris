
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
