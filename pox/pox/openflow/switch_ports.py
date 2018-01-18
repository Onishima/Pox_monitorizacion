import collections

nested_dict = lambda: collections.defaultdict(nested_dict)
src_dst_app = nested_dict()
sw_int_delay = collections.defaultdict(dict)
switch_host = collections.defaultdict(dict)
diff_q_table = collections.defaultdict(dict)
q_table = collections.defaultdict(dict)
d = collections.defaultdict(list)
