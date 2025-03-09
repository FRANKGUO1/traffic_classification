import torch
import os
import random

def merge_and_shuffle_pt_files(directory, output_file='merged_data.pt'):
    """
    合并指定目录中的所有 .pt 文件，并随机打乱数据。
    
    参数:
        directory (str): 包含 .pt 文件的目录路径
        output_file (str): 合并后保存的文件名，默认为 'merged_data.pt'
    
    返回:
        None (直接保存到文件)
    """
    # 检查目录是否存在
    if not os.path.isdir(directory):
        raise ValueError(f"目录 {directory} 不存在！")
    
    # 获取所有 .pt 文件
    pt_files = [f for f in os.listdir(directory) if f.endswith('.pt')]
    if not pt_files:
        raise ValueError(f"目录 {directory} 中没有 .pt 文件！")
    
    # 合并所有数据
    merged_data = []
    for pt_file in pt_files:
        file_path = os.path.join(directory, pt_file)
        data = torch.load(file_path)
        print(f"加载 {file_path}，包含 {len(data)} 个样本")
        merged_data.extend(data)
    
    # 随机打乱数据
    random.shuffle(merged_data)
    print(f"总共合并了 {len(merged_data)} 个样本")
    
    # 保存合并后的数据
    torch.save(merged_data, output_file)
    print(f"合并并打乱后的数据已保存到 {output_file}")

# 示例使用
if __name__ == "__main__":
    # 指定包含 .pt 文件的目录
    input_directory = './data'  # 请替换为你的实际目录路径
    output_filename = 'merged_shuffled_data.pt'
    
    try:
        merge_and_shuffle_pt_files(input_directory, output_filename)
    except Exception as e:
        print(f"发生错误: {e}")