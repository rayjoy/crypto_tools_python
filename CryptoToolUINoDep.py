#!/usr/bin/env python3

"""
Crypto Tool
"""


import wx
import pyDes
import pyaes
from binascii import hexlify, unhexlify
import sys
from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT

import ctypes
from wx.core import ID_ANY

# Query DPI Awareness (Windows 10 and 8)
awareness = ctypes.c_int()
errorCode = ctypes.windll.shcore.GetProcessDpiAwareness(
    0, ctypes.byref(awareness))
# print(awareness.value)
# Set DPI Awareness  (Windows 10 and 8)
errorCode = ctypes.windll.shcore.SetProcessDpiAwareness(2)
# the argument is the awareness level, which can be 0, 1 or 2:
# for 1-to-1 pixel control I seem to need it to be non-zero (I'm using level 2)
# Set DPI Awareness  (Windows 7 and Vista)
success = ctypes.windll.user32.SetProcessDPIAware()
# behaviour on later OSes is undefined,
# although when I run it on my Windows 10 machine,
# it seems to work with effects identical to SetProcessDpiAwareness(1


ENC = 1
DEC = 0
algList = ['aes', 'des', '3des2key', '3des3key', 'sm4']
modeList = ['ecb', 'cbc', 'cfb', 'ofb']
withoutECBModeList = ['cbc', 'cfb', 'ofb']


def _string_to_bytes(text):
    if isinstance(text, bytes):
        return text
    return [ord(c) for c in text]

# In Python 3, we return bytes


def _bytes_to_string(binary):
    return bytes(binary)


def check_data_format(alg, mode, key, iv, data):
    if alg == 'aes':
        if mode in withoutECBModeList and len(iv) != 32:
            return False, 'iv length must be 16, please input right iv.'
        if len(key) != 32:
            return False, 'key length must be 16, please input right key.'
        if len(data) % 32 != 0:
            return False, 'data length must be 16 * N, please input right data.'

    elif alg == 'des':
        if mode in withoutECBModeList and len(iv) != 16:
            return False, 'iv length must be 8, please input right iv.'
        if len(key) != 16:
            return False, 'key length must be 8, please input right key.'
        if len(data) % 16 != 0:
            return False, 'data length must be 8 * N, please input right data.'

    elif alg == '3des2key':
        if mode in withoutECBModeList and len(iv) != 16:
            return False, 'iv length must be 8, please input right iv.'
        if len(key) != 32:
            return False, 'key length must be 16, please input right key.'
        if len(data) % 16 != 0:
            return False, 'data length must be 8 * N, please input right data.'

    elif alg == '3des3key':
        if mode in withoutECBModeList and len(iv) != 16:
            return False, 'iv length must be 8, please input right iv.'
        if len(key) != 48:
            return False, 'key length must be 24, please input right key.'
        if len(data) % 16 != 0:
            return False, 'data length must be 8 * N, please input right data.'

    elif alg == 'sm4':
        if mode in withoutECBModeList and len(iv) != 32:
            return False, 'iv length must be 16, please input right iv.'
        if len(key) != 32:
            return False, 'key length must be 16, please input right key.'
        if len(data) % 32 != 0:
            return False, 'data length must be 16 * N, please input right data.'

    return True, 'data format correct'


def SymmCryptoAES(alg, mode, op, key, iv, data):
    out = ''

    if op == ENC:
        for i in range(int(len(data) / 32)):
            if mode == 'ecb':
                aes = pyaes.AESModeOfOperationECB(unhexlify(key))
            elif mode == 'cbc':
                aes = pyaes.AESModeOfOperationCBC(
                    unhexlify(key), unhexlify(iv))
            elif mode == 'cfb':
                aes = pyaes.AESModeOfOperationCFB(
                    unhexlify(key), unhexlify(iv), segment_size=16)
            elif mode == 'ofb':
                aes = pyaes.AESModeOfOperationOFB(
                    unhexlify(key), unhexlify(iv))

            datab = unhexlify(data[i*32:(i+1)*32])
            encdatab = aes.encrypt(datab)
            if mode != 'ofb':
                outhex = bytes.hex(encdatab)
                iv = outhex
            else:
                ivb = [(x ^ p) for (x, p) in zip(datab, encdatab)]
                iv = bytes.hex(_bytes_to_string(ivb))
                outhex = bytes.hex(encdatab)
            out += outhex

    elif op == DEC:
        for i in range(int(len(data) / 32)):
            if mode == 'ecb':
                aes = pyaes.AESModeOfOperationECB(unhexlify(key))
            elif mode == 'cbc':
                aes = pyaes.AESModeOfOperationCBC(
                    unhexlify(key), unhexlify(iv))
            elif mode == 'cfb':
                aes = pyaes.AESModeOfOperationCFB(
                    unhexlify(key), unhexlify(iv), segment_size=16)
            elif mode == 'ofb':
                aes = pyaes.AESModeOfOperationOFB(
                    unhexlify(key), unhexlify(iv))

            if mode != 'ofb':
                iv = data[i*32:(i+1)*32]
                out += bytes.hex(aes.decrypt(
                    unhexlify(data[i*32:(i+1)*32])))
            else:
                datab = unhexlify(data[i*32:(i+1)*32])
                encdatab = aes.decrypt(datab)
                ivb = []
                for i in range(len(encdatab)):
                    ivb.append(datab[i] ^ encdatab[i])
                iv = bytes.hex(_bytes_to_string(ivb))
                outhex = bytes.hex(encdatab)
                out += outhex
    return out


def SymmCryptoSM4(alg, mode, op, key, iv, data):
    sm4 = Sm4()

    if op == ENC:
        sm4.sm4_set_key(unhexlify(key), ENCRYPT)
    elif op == DEC:
        sm4.sm4_set_key(unhexlify(key), DECRYPT)

    if mode == 'ecb':
        out = bytes.hex(bytes(sm4.sm4_crypt_ecb(
            unhexlify(data))))
    elif mode == 'cbc':
        out = bytes.hex(bytes(sm4.sm4_crypt_cbc(
            unhexlify(iv), unhexlify(data))))
    elif mode == 'cfb':
        out = bytes.hex(bytes(sm4.sm4_crypt_cfb(
            unhexlify(iv), unhexlify(data))))
    elif mode == 'ofb':
        out = bytes.hex(bytes(sm4.sm4_crypt_ofb(
            unhexlify(iv), unhexlify(data))))

    return out


def SymmCryptoDES(alg, mode, op, key, iv, data):
    if alg == 'des':
        des = pyDes.des
    else:
        des = pyDes.triple_des
    if mode == 'ecb':
        k = des(unhexlify(key), pyDes.ECB, None,
                pad=None, padmode=pyDes.PAD_NORMAL)
        if op == ENC:
            out = bytes.hex(k.encrypt(unhexlify(data)))
        elif op == DEC:
            out = bytes.hex(k.decrypt(unhexlify(data)))

    elif mode == 'cbc':
        k = des(unhexlify(key), pyDes.CBC, unhexlify(
            iv), pad=None, padmode=pyDes.PAD_NORMAL)
        if op == ENC:
            out = bytes.hex(k.encrypt(unhexlify(data)))
        elif op == DEC:
            out = bytes.hex(k.decrypt(unhexlify(data)))

    elif mode == 'cfb':
        out = ''
        k = des(unhexlify(key), pyDes.ECB, None,
                pad=None, padmode=pyDes.PAD_NORMAL)
        ivb = unhexlify(iv)
        for i in range(int(len(data) / 16)):
            datab = unhexlify(data[i*16:(i+1)*16])
            enciv = k.encrypt(ivb)
            outb = [(p ^ x) for (p, x) in zip(datab, enciv)]
            if op == ENC:
                ivb = _bytes_to_string(outb)
                out += bytes.hex(ivb)
            elif op == DEC:
                ivb = _bytes_to_string(datab)
                out += bytes.hex(_bytes_to_string(outb))

    elif mode == 'ofb':
        out = ''
        k = des(unhexlify(key), pyDes.ECB, None,
                pad=None, padmode=pyDes.PAD_NORMAL)
        ivb = unhexlify(iv)
        for i in range(int(len(data) / 16)):
            datab = unhexlify(data[i*16:(i+1)*16])
            enciv = k.encrypt(ivb)
            outb = [(p ^ x) for (p, x) in zip(datab, enciv)]
            ivb = _bytes_to_string(enciv)
            out += bytes.hex(_bytes_to_string(outb))

    return out


def SymmCryptoCompute(alg, mode, op, key, iv, data):
    if alg not in algList:
        return False, "algorithm does't support."
    ret, message = check_data_format(alg, mode, key, iv, data)
    if ret == False:
        return ret, message

    if alg == 'aes':
        out = SymmCryptoAES(alg, mode, op, key, iv, data)

    elif alg == 'des' or alg == '3des2key' or alg == '3des3key':
        # if mode in ['cfb', 'ofb']:
        #     return False, "des does't support " + mode + " now"
        out = SymmCryptoDES(alg, mode, op, key, iv, data)

    elif alg == 'sm4':
        out = SymmCryptoSM4(alg, mode, op, key, iv, data)

    return True, str(out)


class TextFrame(wx.Frame):

    def __init__(self, parent, title):
        super(TextFrame, self).__init__(parent, id=ID_ANY, title='Crypto Tool',
                                        size=(800, 700))
        self.InitStatusBar()
        self.InitUI()
        self.Centre()
        self.Show()

    def InitUI(self):
        panel = wx.Panel(self, -1)

        self.keyLabel = wx.StaticText(panel, label="密钥:")
        self.keyText = wx.TextCtrl(
            panel, size=(-1, 40), style=wx.TE_CHARWRAP | wx.TE_MULTILINE)
        self.keyText.SetInsertionPoint(0)

        self.ivLabel = wx.StaticText(panel, label="IV:")
        self.ivText = wx.TextCtrl(
            panel, size=(-1, 40), style=wx.TE_CHARWRAP | wx.TE_MULTILINE)
        self.keyText.SetInsertionPoint(0)

        self.plainLabel = wx.StaticText(panel, label="明文:")
        self.plainText = wx.TextCtrl(
            panel, size=(-1, 80), style=wx.TE_CHARWRAP | wx.TE_MULTILINE)

        self.cipherLabel = wx.StaticText(panel, label="密文:")
        self.cipherText = wx.TextCtrl(
            panel, size=(-1, 80), style=wx.TE_CHARWRAP | wx.TE_MULTILINE)

        self.outdataLabel = wx.StaticText(panel, label="输出信息:")
        self.outdataText = wx.TextCtrl(
            panel, size=(-1, 160), style=wx.TE_CHARWRAP | wx.TE_MULTILINE)

        fgs = wx.FlexGridSizer(5, 2, 9, 25)
        fgs.AddMany([(self.keyLabel), (self.keyText, 1, wx.EXPAND),
                     (self.ivLabel), (self.ivText, 1, wx.EXPAND),
                     (self.plainLabel), (self.plainText, 1, wx.EXPAND),
                     (self.cipherLabel), (self.cipherText, 1, wx.EXPAND),
                     (self.outdataLabel), (self.outdataText, 1, wx.EXPAND)])
        fgs.AddGrowableRow(2, 1)
        fgs.AddGrowableRow(3, 1)
        fgs.AddGrowableRow(4, 1)
        fgs.AddGrowableCol(1, 1)

        self.algList = ['aes', 'des', '3des2key', '3des3key', 'sm4']
        self.algLabel = wx.StaticText(panel, label="算法:")
        self.algChoice = wx.Choice(panel, choices=self.algList)
        self.algChoice.SetSelection(0)

        self.modeList = modeList
        self.modeLabel = wx.StaticText(panel, label="模式:")
        self.modeChoice = wx.Choice(panel, choices=self.modeList)
        self.modeChoice.SetSelection(0)

        self.encButton = wx.Button(panel, label="加密")
        self.Bind(wx.EVT_BUTTON, self.OnClickEnc, self.encButton)
        self.encButton.SetDefault()

        self.decButton = wx.Button(panel, label="解密")
        self.Bind(wx.EVT_BUTTON, self.OnClickDec, self.decButton)
        self.decButton.SetDefault()

        choicefgs = wx.FlexGridSizer(1, 6, 9, 16)
        choicefgs.AddMany([(self.algLabel), (self.algChoice),
                           (self.modeLabel), (self.modeChoice),
                           (self.encButton), (self.decButton)])

        hbox = wx.BoxSizer(wx.VERTICAL)
        hbox.Add(fgs, proportion=1, flag=wx.ALL | wx.EXPAND, border=15)
        hbox.Add(choicefgs, proportion=0, flag=wx.ALL | wx.EXPAND, border=15)

        panel.SetSizer(hbox)

    def InitStatusBar(self):
        self.statusbar = self.CreateStatusBar()
        self.statusbar.SetFieldsCount(3)
        self.statusbar.SetStatusWidths([-2, -5, -1])
        self.statusbar.SetStatusText("Use wxPython", 0)
        self.statusbar.SetStatusText("zhangqinlei@gmail.com", 1)
        self.statusbar.SetStatusText("By ZQL", 2)

    def OnExit(self, event):
        """Close the frame, terminating the application."""
        self.Close(True)

    def OnClickEnc(self, event):
        key = self.keyText.GetLineText(0)
        plain = ''
        for i in range(self.plainText.GetNumberOfLines()):
            plain += self.plainText.GetLineText(i)
        alg = self.algList[self.algChoice.GetSelection()]
        self.outdataText.AppendText("alg: " + alg + "\n")
        mode = self.modeList[self.modeChoice.GetSelection()]
        self.outdataText.AppendText("mode: " + mode + "\n")
        op = ENC
        iv = self.ivText.GetLineText(0)

        ret, out = SymmCryptoCompute(alg, mode, op, key, iv, plain)
        if ret is False:
            self.outdataText.AppendText("error:\n" + out + '\n')
            # self.statusbar.SetStatusText(out, 1)
            return None

        self.cipherText.Clear()
        self.cipherText.AppendText(str(out))
        self.outdataText.AppendText("加密结果:\n" + str(out) + '\n')

    def OnClickDec(self, event):
        key = self.keyText.GetLineText(0)
        ciphertext = ''
        for i in range(self.cipherText.GetNumberOfLines()):
            ciphertext += self.cipherText.GetLineText(i)
        alg = self.algList[self.algChoice.GetSelection()]
        self.outdataText.AppendText("alg: " + alg + "\n")
        mode = self.modeList[self.modeChoice.GetSelection()]
        self.outdataText.AppendText("mode: " + mode + "\n")
        op = DEC
        iv = self.ivText.GetLineText(0)

        ret, out = SymmCryptoCompute(alg, mode, op, key, iv, ciphertext)
        if ret is False:
            self.outdataText.AppendText("error:\n" + out + '\n')
            return None

        self.plainText.Clear()
        self.plainText.AppendText(str(out))
        self.outdataText.AppendText("解密结果:\n" + str(out) + '\n')


if __name__ == '__main__':
    # When this module is run (not imported) then create the app, the
    # frame, show it, and start the event loop.
    app = wx.App()
    frm = TextFrame(None, title='Hello World 2')
    frm.Show()
    app.MainLoop()
