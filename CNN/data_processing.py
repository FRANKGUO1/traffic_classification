# 导入必要的库
import pandas as pd
import numpy as np
import torch
import matplotlib.pyplot as plt


# 定义一个函数来解析时间戳
def parse_timestamp(ts):
    seconds = int(ts)
    microseconds = int((ts - seconds) * 1e6)
    return pd.Timestamp(seconds, unit='s') + pd.Timedelta(microseconds, unit='us')


# 绘图函数（默认不显示）
def plot_flow_window(interval_data, packet_sizes, flow_name, window_idx, t_start, t_end, num_points):
    plt.figure(figsize=(10, 6))
    plt.scatter(interval_data, packet_sizes, s=10)
    plt.xlabel('Time Interval (0-299)')
    plt.ylabel('Packet Size')
    plt.title(f'Flow: {flow_name}, Window {window_idx} ({t_start} to {t_end}), Points: {num_points}')
    plt.grid(True)
    # plt.show()  # 默认不显示，调试时可取消注释


# 将数据转换为模型输入格式并返回图像
def process_to_image(group, t_start):
    # 计算时间差
    group = group.copy()
    group['Delta_t'] = (group['Timestamp'] - t_start).dt.total_seconds()
    group = group[(group['Delta_t'] >= 0) & (group['Delta_t'] < 15)].copy()
    
    # 计算区间
    group.loc[:, 'Interval'] = (group['Delta_t'] / interval_length).astype(int)
    
    # 统计点数
    num_points = len(group)
    if num_points < min_points:
        return None, num_points, None
    
    # 创建一个 (300,) 的向量，表示每个区间的数据包计数
    time_bins = np.zeros(num_intervals)
    for idx in group['Interval']:
        if idx < num_intervals:  # 防止越界
            time_bins[idx] += 1
    
    # 将 Packet_Size 标准化到 0-147
    packet_min, packet_max = group['Packet_Size'].min(), group['Packet_Size'].max()
    if packet_max == packet_min:  # 避免除以零
        packet_max = packet_min + 1
    normalized_sizes = ((group['Packet_Size'] - packet_min) / (packet_max - packet_min) * (target_size - 1)).astype(int)
    
    # 创建 (148, 148) 图像
    image = np.zeros((target_size, target_size), dtype=np.float32)
    # image = np.zeros((target_size, target_size), dtype=np.float32)  # target_size = 148
    print(image.shape)
    for interval, size in zip(group['Interval'], normalized_sizes):
        if interval < num_intervals:  # 防止越界
            target_interval = int(interval * (target_size / num_intervals))
            image[size, target_interval] += 1  # 在对应位置记录计数
    
    return image, num_points, group


class_mapping = {
    'video': 0,
    'voip': 1,
    'audio': 1, # 数据中的audio就是voip，所以类别不做区分
    'ftp': 2,
    'sftp': 2,
    'chat': 3
}

file_path = '/home/sinet/gzc/traffic_classification/CNN/data/youtube_video.csv'
min_points = 50  # 最小点数阈值
data_fliename = file_path.split('/')[-1].split('.')[0]  # 从文件路径中提取应用类别
class_name = data_fliename.split('_')[-1]
print(class_name, class_mapping[class_name])

# 读取CSV文件
df = pd.read_csv(file_path)  # 请替换为你的实际CSV文件路径
# 应用解析函数到Timestamp列
df['Timestamp'] = df['Timestamp'].apply(parse_timestamp)

# 根据五元组分组
group_cols = ['Source_IP', 'Destination_IP', 'Source_Port', 'Destination_Port', 'Protocol']
flows = df.groupby(group_cols)

# 定义时间区间参数
window_length = 15  # 15秒窗口
step_size = 5  # 滑动步长5秒
num_intervals = 300  # 15秒分为300个区间
interval_length = window_length / num_intervals  # 每个区间0.05秒

target_size = 150  # 模型输入尺寸 (150, 150)

# 处理每个流并保存数据
output_data = []  # 存储所有符合条件的图像数据
for name, group in flows:
    t_min = group['Timestamp'].min()
    t_max = group['Timestamp'].max()
    total_seconds = (t_max - t_min).total_seconds()
    
    if total_seconds < window_length:
        # print(f"Flow: {name}, Total duration ({total_seconds:.2f}s) < {window_length}s, skipping")
        continue
    
    num_windows = int((total_seconds - window_length) / step_size) + 1
    
    for i in range(num_windows):
        t_start = t_min + pd.Timedelta(seconds=i * step_size)
        t_end = t_start + pd.Timedelta(seconds=window_length)
        
        image, num_points, window_group = process_to_image(group, t_start)
               
        if image is None:
            # print(f"Skipping flow {name}, Window {i} (points < {min_points})")
            continue
        print(f"Flow: {name}, Window {i} ({t_start} to {t_end}), Number of points: {num_points}")
        # 调用绘图函数（确保 window_group 包含 'Interval'）
        # plot_flow_window(window_group['Interval'], window_group['Packet_Size'], name, i, t_start, t_end, num_points)
        
        # 保存数据：(图像, 分类标识)
        output_data.append({
            'image': image,
            'class': class_mapping[class_name]
        })

# 将数据保存到文件
output_file = f'/home/sinet/gzc/traffic_classification/CNN/pt_data/{data_fliename}_data.pt'
torch.save(output_data, output_file)
print(f"数据已保存到 {output_file}，共 {len(output_data)} 个样本")