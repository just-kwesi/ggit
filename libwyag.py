import argparse
import collections
import configparser
from datetime import datetime
import grp, pwd
from fnmatch import fnmatch
import hashlib
from math import ceil
import os
import re
import sys
import zlib

argparser = argparse.ArgumentParser(description="Unendlichs' content tracker")

argsubparsers = argparser.add_subparsers(title="Commands", dest="command")
argsubparsers.required  = True

def main(argv=sys.argv[1:]):
    args = argparser.parse_args(argv)

    match args.command:
        case "add"          : cmd_add(args)
        case "cat-file"     : cmd_cat_file(args)
        case "check-ignore" : cmd_check_ignore(args)
        case "checkout"     : cmd_checkout(args)
        case "commit"       : cmd_commit(args)
        case "hash-object"  : cmd_hash_object(args)
        case "init"         : cmd_init(args)
        case "log"          : cmd_log(args)
        case "ls-files"     : cmd_ls_files(args)
        case "ls-tree"      : cmd_ls_tree(args)
        case "rev-parse"    : cmd_rev_parse(args)
        case "rm"           : cmd_rm(args)
        case "show-ref"     : cmd_show_ref(args)
        case "status"       : cmd_status(args)
        case "tag"          : cmd_tag(args)
        case _              : print("Bad Command")


class GitRepository(object):
    """A git repository"""
    
    worktree = None
    gitdir = None
    conf = None
    
    def __init__(self, path, force=False) -> None:
        self.worktree = path
        self.gitdir = os.path.join(path, ".git")
        
        if not(force or os.path.isdir(self.gitdir)):
            raise Exception("Not a Git repository %s" % path)
        
        # Read configuration file in .git/config
        self.conf = configparser.ConfigParser()
        cf = repo_file(self,"config")
        
        if cf and os.path.exists(cf):
            self.conf.read([cf])
        elif not force:
            raise Exception("Configuration file is missing")
        
        if not force:
            vers = int(self.conf.get("core","repositoryformatversion"))
            if vers !=0:
                raise Exception('Unsupported repositoryformatversion %s' % vers)
            

def repo_path(repo, *path):
    """Compute path under repo's gitdir."""
    return os.path.join(repo.gitdir, *path)

def repo_file(repo, *path, mkdir=False):
    """Same as repo_path, but create dirname(*path) if absent.  For
example, repo_file(r, \"refs\", \"remotes\", \"origin\", \"HEAD\") will create
.git/refs/remotes/origin."""

    if repo_dir(repo, *path[:-1], mkdir=mkdir):
        return repo_path(repo, *path)

def repo_dir(repo, *path, mkdir=False):
    """Same as repo_path, but mkdir *path if absent if mkdir."""

    path = repo_path(repo, *path)

    if os.path.exists(path):
        if (os.path.isdir(path)):
            return path
        else:
            raise Exception("Not a directory %s" % path)

    if mkdir:
        os.makedirs(path)
        return path
    else:
        return None


def repo_create(path):
    """create a new repository at path"""
    
    repo = GitRepository(path,True)
    
    # first make sure path is empty or doesn't exist
    
    if os.path.exists(repo.worktree):
        if not os.path.isdir(repo.worktree):
            raise Exception ("%s is not a directory!" % path)
        if os.path.exists(repo.gitdir) and os.listdir(repo.gitdir):
            raise Exception("%s is not empty!" % path)
    else:
        os.makedirs(repo.worktree)
        
    
    assert repo_dir(repo, "branches", mkdir=True)
    assert repo_dir(repo, "objects", mkdir=True)
    assert repo_dir(repo, "refs", "tags", mkdir=True)
    assert repo_dir(repo, "refs", "heads", mkdir=True)
    
    # .git/description
    with open(repo_file(repo, "description"), "w") as f:
        f.write("Unnamed repository: edit this file 'description' to name this repository.\n")
    
    # .git/Head
    with open(repo_file(repo,"HEAD"),'w') as f:
        f.write('ref: refs/heads/master\n')
        
    with open(repo_file(repo,"config"), 'w') as f:
        config = repo_default_config()
        config.write(f)
    
    return repo

def repo_find(path=".", required=True):
    path = os.path.realpath(path)
    
    if os.path.isdir(os.path.join(path, ".git")):
        return GitRepository(path)

    # if we haven't returned, recurse in the parent if w
    parent = os.path.realpath(os.path.join(path,".."))
    
    if parent == path:
        # Bottom case
        # os.path.join("/", "..") == "/":
        # If parent==path, then path is root.
        if required:
            raise Exception("No git directory.")
        else:
            return None
    
    # recursive case
    return repo_find(parent,required)

def repo_default_config():
    ret = configparser.ConfigParser()
    
    ret.add_section("core")
    ret.set("core", "repositoryformatversion", "0")
    ret.set("core", "filemode", "false")
    ret.set("core", "bare", "false")

    return ret



class GitObject (object):
    def __init__(self,data=None):
        if data != None:
            self.deserialize(data)
        else:
            self.init()
            
    def init(self):
        pass
    
    def deserialize(self,data):
        raise NotImplementedError
    def serialize(self,repo):
        raise NotImplementedError
    
class GitBlob(GitObject):
    fmt=b'blob'
    
    def serialize(self):
        return self.blobData
    
    def deserialize(self,data):
        self.blobData = data
    
def object_read(repo,sha):
    """Read object sha from Git repository repo.  Return a
    GitObject whose exact type depends on the object."""
    
    path = repo_file(repo, 'objects', sha[0:2],sha[2:])
    
    if not os.path.isfile(path):
        return None
    
    with open(path,'rb') as f:
        raw = zlib.decompress(f.read())
        
        # read object type
        x = raw.find(b' ')
        fmt = raw[0:x]
        
        # read and validate object size
        y = raw.find(b'\x00', x)
        size = int(raw[x:y].decode('ascii'))
        if size != len(raw) - y - 1 :
            raise Exception(f"Malformed object {sha}: bad length")
        
        match fmt:
            case b'commit' : c=GitCommit
            case b'tree'   : c=GitTree
            case b'tag'    : c=GitTag
            case b'blob'   : c=GitBlob
            case _:
                raise Exception(f"Unknown type {fmt.decode("ascii")} for object {sha}")
            
            # call constructor and return object
        return c(raw[y+1:])

def object_write(obj,repo=None):
    data = obj.serialize()
    
    # add header
    result = obj.fmt + b' ' + str(len(data)).encode() + b'\x00' + data
    
    # compute hash
    sha = hashlib.sha1(result).hexdigest()
    
    if repo:
        # compute path
        path = repo_file(repo,'objects', sha[0:2], sha[2:], mkdir=True)
        
        if not os.path.exists(path):
            with open(path, 'wb') as f:
                # compress and write
                f.write(zlib.compress(result))
    return sha



# init repo
argsp = argsubparsers.add_parser('init', help="Initiate a new, empty repository")
argsp.add_argument("path", metavar='directory',nargs='?',default=".",help="Where to create the repository")

# add cat-file command
argsp = argsubparsers.add_parser('cat-file', help="Provide content of objects in a repository")
argsp.add_argument("type", metavar='type', choices=['blob','commit','tag','tree'] ,help="Speccify Type of object to retrieve")
argsp.add_argument('object', metavar='object', help="Object to display")


def cmd_init(args):
    repo_create(args.path)

