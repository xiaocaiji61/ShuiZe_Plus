import os


def run_subfindermain(domain):
    subfinders = []
    subfinder_folder = './Plugins/infoGather/subdomain/subfinder'
    subfinder_file = '{}/{}.txt'.format(subfinder_folder, domain)

    os.system('chmod 777 ./Plugins/infoGather/subdomain/subfinder/subfinder_linux')
    os.system('./Plugins/infoGather/subdomain/subfinder/subfinder_linux -d {} -o {}'.format(domain, subfinder_file))
    try:
        with open(subfinder_file, 'r') as f:
            for each_line in f.read().splitlines():
                subfinders.append(each_line.strip())  # 子域名

        os.remove(subfinder_file)  # 删除临时文件
    except Exception as e:
        subfinders = []

    return list(set(subfinders))
