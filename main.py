"""
参考文章：
http://pentestcorner.com/cracking-microsoft-office-97-03-2007-2010-2013-password-hashes-with-hashcat/

"""

import os
import re
import subprocess
import sys
import tempfile

import click

john_dir = os.path.join('john', 'run')  # John运行目录
hashcat_dir = os.path.join('hashcat')  # hashcat的路径
hashcat_path = 'hashcat'  # hashcat可执行文件的名称
john_path = os.path.join(john_dir, 'john')  # JTR的可执行文件路径
rar2john_path = os.path.join(john_dir, 'rar2john')  # Rar2john的绝对路径
zip2john_path = os.path.join(john_dir, 'zip2john')  # Zip2john的绝对路径
office2john_path = os.path.join(john_dir, 'office2john.py')  # Office2john的绝对路径


def run(command):
    """
    与在命令窗口执行显示效果相同，如有彩色输出可保留，但不能返回结果
    :param command: 命令
    :return:
    """
    subprocess.call(command, shell=True)


def sh(command, print_msg=True):
    """
    实时输出但不可显示彩色，可以获取执行结果
    :param command: 命令
    :param print_msg: 是否打印执行结果
    :return:
    """
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lines = []
    for line in iter(p.stdout.readline, b''):
        line = line.rstrip().decode('gbk')
        if print_msg:
            print(line)
        lines.append(line)
    return lines


def office2john(filename):
    """
    从Office文件中提取加密hash
    :param filename:
    :return:
    """
    result = subprocess.check_output(
        f'{sys.executable} {office2john_path} {filename}',
        shell=True).strip().decode()
    return result


def rar2john(filename):
    """
    从rar文件中提取加密hash
    :param filename:
    :return:
    """
    result = subprocess.check_output(
        f'{rar2john_path} {filename}',
        shell=True).strip().decode()
    return result.replace(filename, os.path.basename(filename))


# 目前存在一些问题，暂时弃用
def zip2john(filename):
    result = subprocess.check_output(
        f'{zip2john_path} {filename}',
        shell=False).strip().decode()
    r1 = re.findall(r'\$pkzip2\$\S+?\$/pkzip2\$', result)
    if r1:
        print(r1[0])
        return 'test:' + r1[0]
    r2 = re.findall(r'\$zip2\$\S+\$/zip2\$', result)
    if r2:
        return 'test:' + r2[0]
    raise Exception('未知的压缩包类型')


# https://hashcat.net/wiki/doku.php?id=example_hashes#legacy_hash_types
mode_dict = {
    'RAR3': 12500,
    'RAR5': 13000
}
office_dict = {
    '2007': 9400,
    '2010': 9500,
    '2013': 9600,
    '0': 9700,
    '1': 9710,
    '2': 9720,
    '3': 9810,
    '4': 9800,
    '5': 9820
}


def hash_to_mode(h):
    t = h.split('$')[1].upper()
    if 'OLDOFFICE' in t:
        ver = h.split('$')[2].split('*')[0]
        if h.find(':::') != -1:
            h = h[:h.find(':::')]
        if ver not in office_dict:
            raise Exception(f'未知的文档类型：{h}')
        return h, office_dict[ver]
    elif 'OFFICE' in t:
        ver = h.split('*')[1]
        if ver not in office_dict:
            raise Exception(f'未知的文档类型：{h}')
        return h, office_dict[ver]
    elif t in mode_dict:
        return h, mode_dict[t]
    raise Exception(f'未知的加密类型：{h}')


def file_to_flag(filename):
    file_ext = filename.split('.')[-1]
    if file_ext in ['doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'mdb']:
        file_hash = office2john(filename)
    elif file_ext in ['rar']:
        file_hash = rar2john(filename)
    else:
        raise Exception(f'未知的文件类型：{file_ext}')
    h, mode = hash_to_mode(file_hash)
    return h, mode


@click.command()
@click.argument('input_file')
@click.argument('output_file')
@click.argument('dict_file')
def crack_file(input_file, output_file, dict_file):
    input_file = os.path.abspath(input_file)
    output_file = os.path.abspath(output_file)
    dict_file = os.path.abspath(dict_file)
    if not os.path.exists(input_file):
        raise Exception('请选择正确的输入文件')
    if not os.path.exists(dict_file):
        raise Exception('请选择正确的字典')
    # Zip文件比较特殊，目前Hashcat对pkzip2算法的支持并不完善，只在最新的Beta版中有支持，并且效果一般
    # 所以这里选择直接用John the ripper对Zip进行解密
    # https://github.com/hashcat/hashcat/issues/69
    #
    if input_file.endswith('.zip'):
        zip_tmp_hash_file = tempfile.mktemp()
        run(f'{zip2john_path} {input_file} > {zip_tmp_hash_file}')
        run(f'{john_path} --pot={output_file} --wordlist={dict_file} {zip_tmp_hash_file}')
    else:
        file_hash, flag = file_to_flag(input_file)
        os.chdir(hashcat_dir)

        cmd = f'{hashcat_path} -a 0 -m {flag} --potfile-disable --username --status -o {output_file} "{file_hash}" {dict_file}'
        print(cmd)
        sh(cmd)


if __name__ == '__main__':
    # file_to_flag(r'test\Desktop.zip')
    crack_file()
